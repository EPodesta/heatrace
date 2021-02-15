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

// File to output memory accesses
ofstream tmp_trace_file;

// Binary name
string img_name;

// Map of page accesses <addr,count>
map<UINT64, UINT64> pagemap [THREADS];

// Map of memory op locations <addr, location>
map<UINT64, string> accessmap [THREADS];

// Structure of code mallocs <addr, size>
map<UINT64, UINT64> mallocs [THREADS];

// Map of normalized addresses
map<UINT64, UINT64> norm_static_addr [THREADS];
map<UINT64, UINT64> norm_heap_addr [THREADS];
map<UINT64, UINT64> norm_stack_addr [THREADS];

// Size of pages
static int page_size;

// Discrete time counter
static int time_counter = 0;

// Struct for stack info
struct STACK {
	UINT64 size;
	UINT64 max;
	UINT64 addr;
} stack;

/*
 * Struct for heap info
 * Noteworthy, this structure is related to the most recent malloc.
 */
struct HEAP {
	UINT64 addr;
	UINT64 size;
} actual_work;

/*
 * This method will be called before each malloc in the binary.
 * Also, it will save the malloc size value in pages.
 * @param retip is the returned instruction pointer.
 * @param size is the malloc size.
 */
VOID premalloc(ADDRINT retip, ADDRINT size) {
	actual_work.size = (size >> page_size);
}

/*
 * This method will be called after each malloc in the binary
 * Also, it will save the address of the pointer in the beginning of the
 * allocated space.
 * Finally, information about the malloc will be added to an array.
 * @param ret is the first address of the allocated memory region.
 */
VOID postmalloc(ADDRINT ret) {
	actual_work.addr = (ret >> page_size);
	mallocs[0][actual_work.addr] = actual_work.size;
}

/*
 * This method will identify the memory op call location.
 * @param tid is the thread identifier.
 * @param addr is the memory op address.
 * @param ctxt is the instruction context information.
 */
VOID call_location(int tid, UINT64 addr, const CONTEXT *ctxt) {
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
/*
 * This method will normalize each memory op address, link with a location in
 * the binary and structure an output file in the following format:
 * "discrete_time addr_normalized".
 * Also, to ease region time and address normalization, norm structures are
 * used.
 * @param ptr is the instruction pointer.
 * @param ctxt is the instruction initial register state.
 * @param addr is the memory op address.
 * @param size is the memory op size.
 * @param tid is the thread identifier.
 */
VOID do_memory_methodology(ADDRINT ptr, const CONTEXT *ctxt, ADDRINT addr, ADDRINT size, THREADID tid) {

	UINT64 addr_normalized = addr >> page_size;
	UINT64 page_limit = (addr_normalized+1)*page_size;
	UINT64 page_limit_normalized = page_limit >> page_size;

	// Escrever em binario para ser mais rápido. Usar o lzo para compactar e
	// deixar mais rápido. SE FOR GARGALO.
	if (addr + size > page_limit && addr < page_limit) {
		// UINT64 upper_threshold = (addr+size) - page_limit;
		// UINT64 lower_threshold = size - upper_threshold;

		if (pagemap[tid][addr_normalized]++ == 0)
			call_location(tid, addr_normalized, ctxt);

		if (pagemap[tid][page_limit_normalized]++ == 0)
			call_location(tid, page_limit_normalized, ctxt);

		tmp_trace_file << ++time_counter << " " << addr_normalized << "\n";
		tmp_trace_file << ++time_counter << " " << page_limit_normalized << "\n";

	} else {
		if (pagemap[tid][addr_normalized]++ == 0)
			call_location(tid, addr_normalized, ctxt);

		tmp_trace_file << ++time_counter << " " << addr<< "\n";
	}
}

/*
 * This method will identify all memory operands from a instruction and iterate
 * over them. For each operand, it is verified if is read or write and the
 * proper method is called.
 * @param ins is the instruction to be instrumented.
 * @param val is extra arguments to the function.
 */
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

/*
 * This method will get the stack address and max size. It will be executed at
 * thread init.
 * @param tid is the thread identifier.
 * @param ctxt is the thread initial register state.
 * @param flags specific flags for the thread.
 * @param v values for the tool callback.
 */
// Aplicação pode mudar de forma dinamica a minha stack.
VOID thread(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	stack.addr = PIN_GetContextReg(ctxt, REG_STACK_PTR) >> page_size;
	stack.max = stack.addr - stack.size;
}

/*
 * This method will find mallocs by name in the code binary and insert calls
 * before and after each malloc.
 * @param img is the code binary image.
 * @param v is the value for the function.
 */
VOID find_malloc(IMG img, VOID *v) {
	if (IMG_IsMainExecutable(img)) {
		img_name = basename(IMG_Name(img).c_str());
	}

	// All allocs call the same function.
    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)premalloc, IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)postmalloc, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }
}

/*
 * This method will be run after the code execution and is responsible to use
 * all the structures to create a file for a summary and to create the final
 * file for our methodology.
 * @param code specific termination code for the application.
 * @param val the tool's callback value.
 */
VOID Fini(INT32 code, VOID* val) {
	tmp_trace_file.close();

	// Overall information file
	ofstream overview_file;
	overview_file.open((img_name + ".overall.info.csv").c_str());

	// Discrete normalized time counter
	UINT64 norm_static_counter = 0;
	UINT64 norm_heap_counter = 0;
	UINT64 norm_stack_counter = 0;

	// Find the smallest heap address to locate static data region
	UINT64 heap_smallest_addr = ULLONG_MAX;
	for (auto it : mallocs[0]) {
		if (it.first <= heap_smallest_addr)
			heap_smallest_addr = it.first;

		cout << "Alloc (Heap): " << it.first << " " << it.second << " " << it.first+it.second << endl;
	}
	cout << "Stack: " << stack.addr << " " << stack.size << " " << stack.max << endl;

	// Locate memory regions based on stack and heap information. Also, it
	// normalizes discrete time.
	for (auto it : pagemap[0]) {
		overview_file << it.first;
		overview_file << ",";
		overview_file << pagemap[0][it.first];
		// if the address is between the stack address and stack max
		// Noteworthy, the stack grows in a high to low memory address manner.
		if (stack.addr >= it.first && it.first >= stack.max) {
			if (norm_stack_addr[0].find(it.first) == norm_stack_addr[0].end())
				norm_stack_addr[0][it.first] = ++norm_stack_counter;
			overview_file << ",Stack";
		// if the address is smaller than the heap, then is static data
		} else if (heap_smallest_addr > it.first) {
			if (norm_static_addr[0].find(it.first) == norm_static_addr[0].end())
				norm_static_addr[0][it.first] = ++norm_static_counter;
			overview_file << ",Data";
		} else {
			// Iterate over all malloc structures from execution.
			for (auto malloc : mallocs[0])
				if (malloc.first <= it.first && it.first <= malloc.first+malloc.second) {
					if (norm_heap_addr[0].find(it.first) == norm_heap_addr[0].end())
						norm_heap_addr[0][it.first] = ++norm_heap_counter;
					overview_file << ",Heap";
				}
		}
		// Write call locations on the output file.
		overview_file << accessmap[0][it.first];
		overview_file << "\n";
	}
	overview_file.close();

	ifstream read_tmp_trace_file("tmp_trace_file.tmp");
	ofstream static_trace_file;
	ofstream heap_trace_file;
	ofstream stack_trace_file;

	// Time variables to normalize overall time based on memory regions.
	UINT64 norm_static_time_init = 0;
	UINT64 norm_heap_time_init = 0;
	UINT64 norm_stack_time_init = 0;
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

		// Get time and address info from file.
		time = strtoul((str.substr(0, pos)).c_str(), NULL, 0);
		str.erase(0, pos + delimiter.length());
		addr = strtoul(str.c_str(), NULL, 0);

		// Locate each region and use the initial time to normalize the time
		// from each region.
		if (stack.addr >= addr && addr >= stack.max) {
			if (norm_stack_time_init == 0)
				norm_stack_time_init = time;
			stack_trace_file << time-(norm_stack_time_init-1) << " " << norm_stack_addr[0][addr];
			stack_trace_file << "\n";
		} else if (heap_smallest_addr > addr) {
			if (norm_static_time_init == 0)
				norm_static_time_init = time;
			static_trace_file << time-(norm_static_time_init-1) << " " << norm_static_addr[0][addr];
			static_trace_file << "\n";
		} else {
			for (auto malloc : mallocs[0])
				if (malloc.first <= addr && addr <= malloc.first+malloc.second) {
					if (norm_heap_time_init == 0)
						norm_heap_time_init = time;
					heap_trace_file << time-(norm_heap_time_init-1) << " " << norm_heap_addr[0][addr];
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
	// Stack size from main thread may be different from others.
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
