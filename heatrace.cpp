#include <iostream>
#include <fstream>
#include <sys/time.h>
#include <sys/resource.h>
#include <cerrno>
#include <stdio.h>
#include <unordered_map>
#include <libelf.h>
#include <execinfo.h>
#include "pin.H"

#define THREADS 1

using namespace std;

static int page_size;

map<UINT64, UINT64> pagemap [THREADS];

struct STACK {
	UINT64 size;
	UINT64 max;
	UINT64 addr;
} stack;

struct HEAP {
	UINT64 addr;
	UINT64 size = 0;
} actual_work;

bool line_is_alloc(const string &line)
{
	if (line.find(".reserve")!=string::npos ||
		line.find(".resize")!=string::npos ||
		line.find("new")!=string::npos ||
		line.find("malloc")!=string::npos ||
		line.find("calloc")!=string::npos ||
		0)
		return true;
	return false;
}

string find_location(const CONTEXT *ctxt);
VOID premalloc(const CONTEXT *ctxt, ADDRINT retip, ADDRINT size) {
	cout << "Premalloc " << (size >> page_size) << endl;
	actual_work.size += (size >> page_size);
}

VOID postmalloc(const CONTEXT *ctxt, ADDRINT ret) {
	cout << "Postmalloc " << (ret >> page_size) << endl;
	actual_work.addr = (ret >> page_size);
}

VOID do_memory_methodology(ADDRINT ptr, ADDRINT addr, ADDRINT size, THREADID tid) {

	UINT64 addr_normalized = addr >> page_size;
	UINT64 page_limit = (addr_normalized+1)*page_size;
	UINT64 page_limit_normalized = page_limit >> page_size;

	if (addr + size > page_limit && addr < page_limit) {
		UINT64 upper_threshold = (addr+size) - page_limit;
		UINT64 lower_threshold = size - upper_threshold;

		pagemap[tid][addr_normalized]++;
		pagemap[tid][page_limit_normalized]++;
	} else
		pagemap[tid][addr_normalized]++;
}

VOID trace_memory(INS ins, VOID *val) {
	UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)do_memory_methodology, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_THREAD_ID, IARG_END);
        }

        if (INS_MemoryOperandIsWritten(ins, memOp)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)do_memory_methodology, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_MEMORYWRITE_SIZE, IARG_THREAD_ID, IARG_END);
        }
    }
}

string find_location(const CONTEXT *ctxt)
{
	string res = "";
	void* buf[128];

	PIN_LockClient();

	int nptrs = PIN_Backtrace(ctxt, buf, sizeof(buf)/sizeof(buf[0]));
	char** bt = backtrace_symbols(buf, nptrs);


	for (int i = nptrs-1; i >= 0; i--) {
		res += bt[i];
		res += " ";

		string line=bt[i];
		size_t start = line.find("(");
		if (start!=string::npos && line.substr(start+1, 4) != "/usr") {
			size_t end = line.find(":");
			string file = line.substr(start+1,end-start-1);
			size_t endf = line.find(")");
			int linenum = Uint64FromString(line.substr(end+1, endf-end-1));

			ifstream fstr(file.c_str());
			string l;
	        for(int i=0; i< linenum; ++i)
	            getline(fstr, l);

	        if (line_is_alloc(l)) {
		        cout << l << endl;
		        PIN_UnlockClient();
		        return line.substr(start+1, endf-start-1);
	        }
	        fstr.close();
		}



	}

	PIN_UnlockClient();
	return res;
}

VOID thread(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	stack.addr = PIN_GetContextReg(ctxt, REG_STACK_PTR) >> page_size;
	stack.max = stack.addr - stack.size;
}

VOID find_code_allocation(IMG img, VOID *v)
{
    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)premalloc, IARG_CONST_CONTEXT, IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)postmalloc, IARG_CONST_CONTEXT, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

}

VOID Fini(INT32 code, VOID* val) {
	ofstream f;
	f.open("test");

	cout << actual_work.addr << " " << actual_work.size << " " << actual_work.size+actual_work.addr << endl;
	for (auto it : pagemap[0]) {
		// cout << it.first << endl;
		f << it.first;
		f << ",";
		f << pagemap[0][it.first];
		if (stack.addr >= it.first && it.first >= stack.max)
			f << ",Stack";
		else if (actual_work.addr <= it.first && it.first <= actual_work.addr+actual_work.size)
			f << ",Heap";
		else if (actual_work.addr >= it.first)
			f << ",Data";
		f << "\n";
	}
	f.close();
}

int main (int argc, char **argv) {
	PIN_InitSymbols();
	if (PIN_Init(argc,argv)) return 1;
	page_size = 12;

	struct rlimit sl;
	int ret = getrlimit(RLIMIT_STACK, &sl);
	if (ret == -1)
		cerr << "Error getting stack size. errno: " << errno << endl;
	else
		stack.size = sl.rlim_cur >> page_size;

	/* Instruction functions. */
	IMG_AddInstrumentFunction(find_code_allocation, 0);
	/* Instruction functions. */
	INS_AddInstrumentFunction(trace_memory, 0);
	/* Thread Start */
	PIN_AddThreadStartFunction(thread, 0);

	/* Final function. */
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();
	return 0;
}
