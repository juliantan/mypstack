//

#include "stdafx.h"
#include "profiler/profilerthread.h"
#include "profiler/debugger.h"
#include "utils/dbginterface.h"

struct AttachInfo
{
	AttachInfo();
	~AttachInfo();

	HANDLE process_handle;
	std::vector<HANDLE> thread_handles;
	SymbolInfo *sym_info;
	int limit_profile_time;
};

int _tmain(int argc, _TCHAR* argv[])
{
	if (!dbgHelpInit())
	{
		abort();
		return -1;
	}
	DWORD processId = 4652;
	Debugger *dbg = new Debugger(processId);
	dbg->Attach();
	getchar();
	//dbg->Detach();

	AttachInfo info;
	info.process_handle = dbg->getProcess()->getProcessHandle();
	std::vector<ThreadInfo> vt;
	dbg->getThreads(vt);
	for (size_t i = 0; i < vt.size(); i++)
	{
		ThreadInfo &t = vt[i];
		info.thread_handles.push_back(t.getThreadHandle());
	}
	info.sym_info = new SymbolInfo();
	info.sym_info->loadSymbols(info.process_handle, false);
	ProfilerThread* profilerthread = new ProfilerThread(
		info.process_handle,
		info.thread_handles,
		info.sym_info
	);
	profilerthread->launch(false, THREAD_PRIORITY_TIME_CRITICAL);
	system("pause");
	profilerthread->commit_suicide = true;
	system("pause");
	return 0;
}

