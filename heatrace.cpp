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

/*
 * File to output memory accesses
 */
ofstream tmp_trace_file;

/*
 * Binary name
 */
string img_name;

/*
 * Size of pages
 */
static int page_size;

/*
 * Discrete time counter
 */
static int time_counter = 0;

/*
 * Map of page accesses <addr,count>
 */
map<UINT64, UINT64> pagemap [THREADS];

/*
 * Map of memory op locations <addr, location>
 */
map<UINT64, string> accessmap [THREADS];

/*
 * Structure of code allocs <addr, size>
 */
map<UINT64, UINT64> allocs [THREADS];

/*
 * Map of normalized addresses <addr, norm_addr>
 */
map<UINT64, UINT64> norm_static_addr [THREADS];
map<UINT64, UINT64> norm_heap_addr [THREADS];
map<UINT64, UINT64> norm_stack_addr [THREADS];

/*
 * Struct for stack info
 */
struct STACK {
	UINT64 size;
	UINT64 max;
	UINT64 addr;
} stack;

/*
 * Struct for heap info
 * Noteworthy, this structure is related to the most recent allocation.
 */
struct HEAP {
	UINT64 addr;
	UINT64 size;
} actual_work;

/*
 * Struct for static data info
 */
struct STATIC_DATA {
	UINT64 size;
	UINT64 max;
	UINT64 addr;
};

/*
 * All regions considered by our methodology.
 */
struct STATIC_DATA rodata;
struct STATIC_DATA data;
struct STATIC_DATA bss;

/*
 * This method will be called before each malloc in the binary.
 * Also, it will save the malloc size value in pages.
 * @param retip is the returned instruction pointer.
 * @param size is the malloc size.
 */
VOID premalloc(ADDRINT retip, UINT64 size) {
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

	if (!(allocs[0].find(actual_work.addr) == allocs[0].end())) {
		if (allocs[0][actual_work.addr] <= actual_work.size)
			allocs[0][actual_work.addr] = actual_work.size;
	} else {
		allocs[0][actual_work.addr] = actual_work.size;
	}

	cout << "# Malloc" << endl;
	cout << "Addr: " << actual_work.addr << " Size: " << allocs[0][actual_work.addr] << endl;
}

/*
 * This method will be called before each calloc in the binary.
 * Also, it will save the calloc size value in pages.
 * @param retip is the returned instruction pointer.
 * @param size is the calloc size.
 */
VOID precalloc(ADDRINT retip, UINT64 num_elements, UINT64 element_size) {
	actual_work.size = ((num_elements*element_size) >> page_size);
}

/*
 * This method will be called after each calloc in the binary
 * Also, it will save the address of the pointer in the beginning of the
 * allocated space.
 * Finally, information about the calloc will be added to an array.
 * @param ret is the first address of the allocated memory region.
 */
VOID postcalloc(ADDRINT ret) {
	actual_work.addr = (ret >> page_size);
	allocs[0][actual_work.addr] = actual_work.size;

	cout << "# Calloc" << endl;
	cout << "Addr: " << actual_work.addr << " Size: " << allocs[0][actual_work.addr] << endl;
}

/*
 * This method will be called before each realloc in the binary.
 * Also, it will save the realloc size value in pages.
 * @param retip is the returned instruction pointer.
 * @param size is the realloc size.
 */
VOID prerealloc(ADDRINT retip, ADDRINT heap_ptr, UINT64 size) {
	ADDRINT heap_ptr_normalized = (heap_ptr >> page_size);
	actual_work.size = (size >> page_size);

	if (!(allocs[0].find(heap_ptr_normalized) == allocs[0].end()))
		if (allocs[0][heap_ptr_normalized] >= (size >> page_size))
			actual_work.size = allocs[0][heap_ptr_normalized];
}

/*
 * This method will be called after each realloc in the binary
 * Also, it will save the address of the pointer in the beginning of the
 * allocated space.
 * Finally, information about the realloc will be added to an array.
 * @param ret is the first address of the allocated memory region.
 */
VOID postrealloc(ADDRINT ret) {
	actual_work.addr = (ret >> page_size);
	allocs[0][actual_work.addr] = actual_work.size;

	cout << "# Realloc" << endl;
	cout << "Addr: " << actual_work.addr << " Size: " << allocs[0][actual_work.addr] << endl;
}

/*
 * This method will be called before each aligned_alloc in the binary.
 * Also, it will save the aligned_alloc size value in pages.
 * @param retip is the returned instruction pointer.
 * @param size is the aligned_alloc size.
 */
VOID prememalign(ADDRINT retip, UINT64 size) {
	actual_work.size = (size >> page_size);
}

/*
 * This method will be called after each aligned_alloc in the binary
 * Also, it will save the address of the pointer in the beginning of the
 * allocated space.
 * Finally, information about the aligned_alloc will be added to an array.
 * @param ret is the first address of the allocated memory region.
 */
VOID postmemalign(ADDRINT ret) {
	actual_work.addr = (ret >> page_size);

	if (!(allocs[0].find(actual_work.addr) == allocs[0].end())) {
		if (allocs[0][actual_work.addr] <= actual_work.size)
			allocs[0][actual_work.addr] = actual_work.size;
	} else {
		allocs[0][actual_work.addr] = actual_work.size;
	}

	cout << "# Memory Align" << endl;
	cout << "Addr: " << actual_work.addr << " Size: " << allocs[0][actual_work.addr] << endl;
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

	if (addr + size > page_limit && addr < page_limit) {

		if (pagemap[tid][addr_normalized]++ == 0)
			call_location(tid, addr_normalized, ctxt);

		if (pagemap[tid][page_limit_normalized]++ == 0)
			call_location(tid, page_limit_normalized, ctxt);

		tmp_trace_file << ++time_counter << " " << addr_normalized << "\n";
		tmp_trace_file << ++time_counter << " " << page_limit_normalized << "\n";

	} else {
		if (pagemap[tid][addr_normalized]++ == 0)
			call_location(tid, addr_normalized, ctxt);

		tmp_trace_file << ++time_counter << " " << addr_normalized << "\n";
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
 * This method will identify the static data region.
 * Initially, our methodology selects .rodata, .data and .bss. For more regions,
 * it is possible to add them in the grep call or use a more sophisticated
 * argument method.
 * @param file is the executable file name.
 */
VOID static_data_region(const char *file) {

	char cmd[1024];
	sprintf(cmd, "objdump -h %s | grep -E \"\\.data|\\.rodata|\\.bss\" | awk '{print $2 \" \" strtonum(\"0x\" $4) \" \" strtonum(\"0x\" $3)}'", file);

	FILE *p = popen(cmd, "r");
	cout << "## " << file << " memory addresses:" << endl;

	char line[1024];
	char *static_data;
	UINT64 static_data_addr;
	UINT64 static_data_size;

	cout << "# Static Data" << endl;
	while (fgets(line, sizeof(line), p) != NULL) {
		static_data = strtok(line, " ");
		static_data_addr = atoi(strtok(NULL, " ")) >> page_size;
		static_data_size = atoi(strtok(NULL, "\n")) >> page_size;
		if (strcmp(static_data, ".rodata") == 0) {
			rodata.addr = static_data_addr;
			rodata.size = static_data_size;
		} else if (strcmp(static_data, ".data") == 0) {
			data.addr = static_data_addr;
			data.size = static_data_size;
		} else if (strcmp(static_data, ".bss") == 0) {
			bss.addr = static_data_addr;
			bss.size = static_data_size;
		}
		cout << "Addr: " << static_data_addr << " Size: " << static_data_size << " Name: " << static_data << endl;
	}
	pclose(p);
}

/*
 * This method will get the stack address and max size. It will be executed at
 * thread init. NOTE: the application may change stack size dynamically. If this
 * occurs, we need a more specific thread function.
 * @param tid is the thread identifier.
 * @param ctxt is the thread initial register state.
 * @param flags specific flags for the thread.
 * @param v values for the tool callback.
 */
VOID thread(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	stack.addr = PIN_GetContextReg(ctxt, REG_STACK_PTR) >> page_size;
	stack.max = stack.addr - stack.size;
}

/*
 * This method will find allocs by name in the code binary and insert calls
 * before and after each alloc.
 * @param img is the code binary image.
 * @param v is the value for the function.
 */
VOID find_alloc(IMG img, VOID *v) {
	if (IMG_IsMainExecutable(img)) {
		img_name = basename(IMG_Name(img).c_str());
		static_data_region(img_name.c_str());
	}

    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)premalloc, IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)postmalloc, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

    RTN callocRtn = RTN_FindByName(img, "calloc");
    if (RTN_Valid(callocRtn))
    {
        RTN_Open(callocRtn);

        RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)precalloc, IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)postcalloc, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(callocRtn);
    }

    RTN reallocRtn = RTN_FindByName(img, "realloc");
    if (RTN_Valid(reallocRtn))
    {
        RTN_Open(reallocRtn);

        RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)prerealloc, IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)postrealloc, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(reallocRtn);
    }

	/*
	 * This rtn is only due to consistency purposes. More precisely, some
	 * comparisons were made and an alignment was needed.
	 */
    RTN aligned_allocRtn = RTN_FindByName(img, "aligned_alloc");
    if (RTN_Valid(aligned_allocRtn))
    {
        RTN_Open(aligned_allocRtn);

        RTN_InsertCall(aligned_allocRtn, IPOINT_BEFORE, (AFUNPTR)prememalign, IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(aligned_allocRtn, IPOINT_AFTER, (AFUNPTR)postmemalign, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(aligned_allocRtn);
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

	/*
	 * Overall information file
	 */
	ofstream overview_file;
	overview_file.open((img_name + ".overall.info.csv").c_str());

	/*
	 * Discrete normalized time counter
	 */
	UINT64 norm_static_counter = 0;
	UINT64 norm_heap_counter = 0;
	UINT64 norm_stack_counter = 0;

	cout << "# Stack" << endl;
	cout << "Addr: " << stack.addr << " Size: " << stack.size << " Limit: " << stack.max << endl;

	/*
	 * Locate memory regions based on stack and heap information. Also, it
	 * normalizes discrete time.
	 */
	for (auto it : pagemap[0]) {
		overview_file << it.first;
		overview_file << ",";
		overview_file << pagemap[0][it.first];
		/*
		 * If the address is between the stack address and stack max
		 * Noteworthy, the stack grows in a high to low memory address manner.
		 */
		if (stack.addr >= it.first && it.first >= stack.max) {
			if (norm_stack_addr[0].find(it.first) == norm_stack_addr[0].end()) {
				norm_stack_addr[0][it.first] = ++norm_stack_counter;
				overview_file << ",Stack";
			}
		/*
		 * If the address is in any of the static data structures.
		 */
		} else if ((bss.addr <= it.first && it.first <= bss.addr+bss.size)
				   || (data.addr <= it.first && it.first <= data.addr+bss.size)
				   || (rodata.addr <= it.first && it.first <= rodata.addr+bss.size)) {
			if (norm_static_addr[0].find(it.first) == norm_static_addr[0].end()) {
				norm_static_addr[0][it.first] = ++norm_static_counter;
				overview_file << ",Data";
			}
		} else {
			/*
			 * Iterate over all malloc structures from execution.
			 */
			for (auto alloc : allocs[0])
				if (alloc.first <= it.first && it.first <= alloc.first+alloc.second)
					if (norm_heap_addr[0].find(it.first) == norm_heap_addr[0].end()) {
						norm_heap_addr[0][it.first] = ++norm_heap_counter;
						overview_file << ",Heap" << "," << norm_heap_addr[0][it.first];
					}
		}
		/*
		 * Write call locations on the output file.
		 */
		overview_file << accessmap[0][it.first];
		overview_file << "\n";
	}
	overview_file.close();

	ifstream read_tmp_trace_file("tmp_trace_file.tmp");
	ofstream static_trace_file;
	ofstream heap_trace_file;
	ofstream stack_trace_file;

	/*
	 * Time variables to normalize overall time based on memory regions.
	 */
	UINT64 norm_static_time_init = 0;
	UINT64 norm_heap_time_init = 0;
	UINT64 norm_stack_time_init = 0;
	string str;

	static_trace_file.open((img_name + ".static.trace.csv").c_str());
	heap_trace_file.open((img_name + ".heap.trace.csv").c_str());
	stack_trace_file.open((img_name + ".stack.trace.csv").c_str());

	/*
	 * This code expects a format like: "time count"
	 */
	while (getline(read_tmp_trace_file, str)) {
		UINT64 addr;
		UINT64 time;
		string delimiter = " ";

		size_t pos = str.find(delimiter);

		/*
		 * Get time and address info from file.
		 */
		time = strtoul((str.substr(0, pos)).c_str(), NULL, 0);
		str.erase(0, pos + delimiter.length());
		addr = strtoul(str.c_str(), NULL, 0);

		/*
		 * Locate each region and use the initial time to normalize the time
		 * from each region.
		 */
		if (stack.addr >= addr && addr >= stack.max) {
			if (norm_stack_time_init == 0)
				norm_stack_time_init = time;
			stack_trace_file << time-(norm_stack_time_init-1) << " " << norm_stack_addr[0][addr];
			stack_trace_file << "\n";
		} else if ((bss.addr <= addr && addr <= bss.addr+bss.size)
				   || (data.addr <= addr && addr <= data.addr+bss.size)
				   || (rodata.addr <= addr && addr <= rodata.addr+bss.size)) {
			if (norm_static_time_init == 0)
				norm_static_time_init = time;
			static_trace_file << time-(norm_static_time_init-1) << " " << norm_static_addr[0][addr];
			static_trace_file << "\n";
		} else {
			for (auto alloc : allocs[0])
				if (alloc.first <= addr && addr <= alloc.first+alloc.second) {
					if (norm_heap_time_init == 0)
						norm_heap_time_init = time;
					heap_trace_file << time-(norm_heap_time_init-1) << " " << norm_heap_addr[0][addr];
					heap_trace_file << "\n";
					break;
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

	/* System page size. */
	page_size = 12;

	tmp_trace_file.open("tmp_trace_file.tmp");

	struct rlimit sl;

	/* Stack size from main thread may be different from others. */
	int ret = getrlimit(RLIMIT_STACK, &sl);
	if (ret == -1)
		cerr << "Error getting stack size. errno: " << errno << endl;
	else
		stack.size = sl.rlim_cur >> page_size;

	/* Instruction functions. */
	IMG_AddInstrumentFunction(find_alloc, 0);
	/* Instruction functions. */
	INS_AddInstrumentFunction(trace_memory, 0);
	/* Thread Start */
	PIN_AddThreadStartFunction(thread, 0);

	/* Final function. */
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();
	return 0;
}
