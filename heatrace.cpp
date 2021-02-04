#include <iostream>
#include <fstream>
#include <sys/time.h>
#include <sys/resource.h>
#include <string>
#include <cerrno>
#include <stdio.h>
#include <unordered_map>
#include <libelf.h>
#include <execinfo.h>
#include <limits.h>
#include "pin.H"

#define THREADS 1

using namespace std;

// Size of pages
static int page_size;

// Discrete time counter
static int time_counter = 0;

// File to output memory accesses
ofstream tmp_trace_file;

// Binary name
string img_name;

// Map of page accesses <addr,count>
map<UINT64, UINT64> pagemap [THREADS];

// Map of memory op locations <addr, location>
map<UINT64, string> accessmap [THREADS];

// Number of mallocs <addr, size>
map<UINT64, UINT64> mallocs [THREADS];

// Struct for stack info
struct STACK {
	UINT64 size;
	UINT64 max;
	UINT64 addr;
} stack;

// Struct for heap info
struct HEAP {
	UINT64 addr;
	UINT64 size = 0;
} actual_work;

// Get timestamp count (CPU Cycle)
static inline UINT64 get_tsc() {
	#if defined(__i386) || defined(__x86_64__)
		unsigned int lo, hi;
		__asm__ __volatile__ (
			"cpuid \n"
			"rdtsc"
			: "=a"(lo), "=d"(hi) /* outputs */
			: "a"(0)             /* inputs */
			: "%ebx", "%ecx");   /* clobbers*/
	  return ((UINT64)lo) | (((UINT64)hi) << 32);
	#elif defined(__ia64)
		UINT64 r;
		__asm__ __volatile__ ("mov %0=ar.itc" : "=r" (r) :: "memory");
		return r;
	#elif defined(__powerpc__)
		UINT64 hi, lo, tmp;
		__asm__ volatile(
			"0:\n"
			"mftbu   %0 \n"
			"mftb    %1 \n"
			"mftbu   %2 \n"
			"cmpw    %2,%0 \n"
			"bne     0b \n"
			: "=r"(hi),"=r"(lo),"=r"(tmp) );
		return ((UINT64)lo) | (((UINT64)hi) << 32);
	#else
		#error "architecture not supported"
	#endif
}

VOID premalloc(ADDRINT retip, ADDRINT size) {
	actual_work.size = (size >> page_size);
}

VOID postmalloc(ADDRINT ret) {
	actual_work.addr = (ret >> page_size);
	mallocs[0][actual_work.addr] = actual_work.size;
}

VOID insert_call_location(int tid, UINT64 addr, const CONTEXT *ctxt) {
	string fname;
	int col, line;
	PIN_LockClient();
	PIN_GetSourceLocation(PIN_GetContextReg(ctxt,REG_INST_PTR), &col, &line, &fname);
	PIN_UnlockClient();
	if (fname == "")
		accessmap[tid][addr] = ",unknown.location";
	else
		accessmap[tid][addr] = "," + fname + ":" + decstr(line);
}

VOID do_memory_methodology(ADDRINT ptr, const CONTEXT *ctxt, ADDRINT addr, ADDRINT size, THREADID tid) {

	UINT64 addr_normalized = addr >> page_size;
	UINT64 page_limit = (addr_normalized+1)*page_size;
	UINT64 page_limit_normalized = page_limit >> page_size;

	if (addr + size > page_limit && addr < page_limit) {
		UINT64 upper_threshold = (addr+size) - page_limit;
		UINT64 lower_threshold = size - upper_threshold;

		if (pagemap[tid][addr_normalized]++ == 0)
			insert_call_location(tid, addr_normalized, ctxt);

		if (pagemap[tid][page_limit_normalized]++ == 0)
			insert_call_location(tid, page_limit_normalized, ctxt);

		tmp_trace_file << ++time_counter << " " << addr_normalized << "\n";
		tmp_trace_file << ++time_counter << " " << page_limit_normalized << "\n";

	} else {
		if (pagemap[tid][addr_normalized]++ == 0)
			insert_call_location(tid, addr_normalized, ctxt);

		tmp_trace_file << ++time_counter << " " << addr_normalized << "\n";
	}
}

VOID trace_memory(INS ins, VOID *val) {
	UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)do_memory_methodology, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_THREAD_ID, IARG_END);
        }

        if (INS_MemoryOperandIsWritten(ins, memOp)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)do_memory_methodology, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_THREAD_ID, IARG_END);
        }
    }
}

VOID thread(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	stack.addr = PIN_GetContextReg(ctxt, REG_STACK_PTR) >> page_size;
	stack.max = stack.addr - stack.size;
}

VOID find_malloc(IMG img, VOID *v) {
	if (IMG_IsMainExecutable(img)) {
		img_name = basename(IMG_Name(img).c_str());
	}

    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)premalloc, IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)postmalloc, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

}

VOID Fini(INT32 code, VOID* val) {
	tmp_trace_file.close();

	ofstream overview_file;
	overview_file.open((img_name + ".overall.info.csv").c_str());

	UINT64 smallest_addr = ULLONG_MAX;
	for (auto it : mallocs[0]) {
		if (it.first <= smallest_addr)
			smallest_addr = it.first;

		cout << "Alloc (Heap): " << it.first << " " << it.second << " " << it.first+it.second << endl;
	}
	cout << "Stack: " << stack.addr << " " << stack.size << " " << stack.max << endl;

	for (auto it : pagemap[0]) {
		overview_file << it.first;
		overview_file << ",";
		overview_file << pagemap[0][it.first];
		if (stack.addr >= it.first && it.first >= stack.max)
			overview_file << ",Stack";
		else if (smallest_addr >= it.first)
			overview_file << ",Data";
		else {
			for (auto it2 : mallocs[0])
				if (it2.first <= it.first && it.first <= it2.first+it2.second)
					overview_file << ",Heap";
		}
		overview_file << accessmap[0][it.first];
		overview_file << "\n";
	}
	overview_file.close();

	ifstream read_tmp_trace_file("tmp_trace_file.tmp");
	ofstream static_trace_file;
	ofstream heap_trace_file;
	ofstream stack_trace_file;
	string str;

	static_trace_file.open((img_name + ".static.trace.csv").c_str());
	heap_trace_file.open((img_name + ".heap.trace.csv").c_str());
	stack_trace_file.open((img_name + ".stack.trace.csv").c_str());

	// This code expects a format like: "time count"
	while (getline(read_tmp_trace_file, str)) {
		UINT64 addr;
		UINT64 time;
		string delimiter = " ";

		size_t pos = str.find(delimiter);

		time = strtoul((str.substr(0, pos)).c_str(), NULL, 0);
		str.erase(0, pos + delimiter.length());
		addr = strtoul(str.c_str(), NULL, 0);

		if (stack.addr >= addr && addr >= stack.max) {
			stack_trace_file << time << " " << addr;
			stack_trace_file << "\n";
		} else if (smallest_addr >= addr) {
			static_trace_file << time << " " << addr;
			static_trace_file << "\n";
		} else {
			for (auto it2 : mallocs[0])
				if (it2.first <= addr && addr <= it2.first+it2.second) {
					heap_trace_file << time << " " << addr;
					heap_trace_file << "\n";
				}
		}
	}

	static_trace_file.close();
    heap_trace_file.close();
	stack_trace_file.close();
}

int main (int argc, char **argv) {
	PIN_InitSymbols();
	if (PIN_Init(argc,argv)) return 1;
	page_size = 12;

	tmp_trace_file.open("tmp_trace_file.tmp");
	struct rlimit sl;
	int ret = getrlimit(RLIMIT_STACK, &sl);
	if (ret == -1)
		cerr << "Error getting stack size. errno: " << errno << endl;
	else
		stack.size = sl.rlim_cur >> page_size;

	/* Instruction functions. */
	IMG_AddInstrumentFunction(find_malloc, 0);
	/* Instruction functions. */
	INS_AddInstrumentFunction(trace_memory, 0);
	/* Thread Start */
	PIN_AddThreadStartFunction(thread, 0);

	/* Final function. */
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();
	return 0;
}
