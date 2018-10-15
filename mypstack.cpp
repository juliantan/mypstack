//

#include "stdafx.h"
#include "profiler/profilerthread.h"
#include "profiler/debugger.h"
#include "utils/dbginterface.h"
//#include "wxProfilerGUI/database.h"

struct AttachInfo
{
	AttachInfo();
	~AttachInfo();

	HANDLE process_handle;
	std::vector<HANDLE> thread_handles;
	SymbolInfo *sym_info;
	int limit_profile_time;
};


#include <wx/config.h>
#include <wx/app.h>
#include <wx/listctrl.h>
#include <wx/splitter.h>
#include <wx/notebook.h>
#include <wx/aui/aui.h>
#include <wx/progdlg.h>
#include <wx/wfstream.h>
#include <wx/zipstrm.h>
#include <wx/txtstrm.h>
#include <wx/cmdline.h>
#include <wx/evtloop.h>
#include <wx/tipwin.h>
#include <string>
#include <vector>
#include <map>
//#include "profilergui.h"
#include "utils/container.h"
#include "utils/stringutils.h"
//#include "wxProfilerGUI/sourceview.h"
#include <wx/mstream.h>
#include <fstream>
#include <set>
#include "profiler/symbolinfo.h"
#include <algorithm>
#include "appinfo.h"
#include "utils/except.h"

class Database
{
public:
	typedef unsigned long long Address;
	typedef size_t FileID;
	typedef size_t ModuleID;

	/// Represents one function (as it appears in function lists).
	struct Symbol
	{
		/// Note: IDs may not persist across DB reloads
		/// (e.g. due to changes in symbol load settings).
		/// Use addresses to persistently refer to symbols in the GUI.
		typedef size_t ID;
		ID id;

		/// Points to the address of the start of the symbol
		/// (or the closest thing we have to that).
		/// Multiple addresses may belong to the same symbol.
		Address  address;

		std::wstring procname;
		FileID       sourcefile;
		ModuleID     module;

		bool isCollapseFunction;
		bool isCollapseModule;
	};

	/// Represents one address we encountered during profiling
	struct AddrInfo
	{
		AddrInfo() : symbol(NULL), sourceline(0), count(0), percentage(0) {}

		// Symbol info
		const Symbol *symbol;
		unsigned      sourceline;

		// IP counts
		double count;
		float  percentage;
	};

	struct Item
	{
		const Symbol *symbol;

		/// Might be different from symbol->address
		/// (e.g. it's the call site for callstacks).
		Address address;

		double inclusive, exclusive;
	};

	struct List
	{
		List() { totalcount = 0; }

		std::vector<Item> items;
		double totalcount;
	};

	struct CallStack
	{
		std::vector<Address> addresses;

		// symbols[i] == addrsymbols[addresses[i]]. For convenience/performance.
		std::vector<const Symbol *> symbols;

		double samplecount;
	};

	Database();
	virtual ~Database();
	void clear();

	void loadFromPath(const std::wstring& profilepath,bool collapseOSCalls,bool loadMinidump);
	void reload(bool collapseOSCalls, bool loadMinidump);

	const Symbol *getSymbol(Symbol::ID id) const { return symbols[id]; }
	Symbol::ID getSymbolCount() const { return symbols.size(); }
	const std::wstring &getFileName(FileID id) const { return files[id]; }
	FileID getFileCount() const { return files.size(); }
	const std::wstring &getModuleName(ModuleID id) const { return modules[id]; }
	ModuleID getModuleCount() const { return modules.size(); }

	const AddrInfo *getAddrInfo(Address addr) { return &addrinfo.at(addr); }

	void setRoot(const Symbol *root);
	const Symbol *getRoot() const { return currentRoot; }

	const List &getMainList() const { return mainList; }
	List getCallers(const Symbol *symbol) const;
	List getCallees(const Symbol *symbol) const;
	std::vector<const CallStack*> getCallstacksContaining(const Symbol *symbol) const;
	std::vector<double> getLineCounts(FileID sourcefile);

	std::vector<std::wstring> stats;

	std::wstring getProfilePath() const { return profilepath; }

	bool has_minidump;

private:
	/// Symbol::ID -> Symbol*
	std::vector<Symbol *> symbols;

	/// filename <-> FileID
	std::vector<std::wstring> files;
	std::unordered_map<std::wstring, FileID> filemap;

	/// module name <-> ModuleID
	std::vector<std::wstring> modules;
	std::unordered_map<std::wstring, ModuleID> modulemap;

	/// Address -> module/procname/sourcefile/sourceline
	std::unordered_map<Address, AddrInfo> addrinfo;

	std::vector<CallStack> callstacks;
	List mainList;
	std::wstring profilepath;
	const Symbol *currentRoot;

	void loadSymbols(wxInputStream &file);
	void loadCallstacks(wxInputStream &file,bool collapseKernelCalls);
	void loadIpCounts(wxInputStream &file);
	void loadStats(wxInputStream &file);
	void loadMinidump(wxInputStream &file);
	void scanMainList();

	bool includeCallstack(const CallStack &callstack) const;

	// Any additional symbols we can load after opening a capture
	class LateSymbolInfo *late_sym_info;
};

#include <windows.h>
#include <Dbgeng.h>
#include "utils/dbginterface.h"
#include <comdef.h>
#include <sstream>
class LateSymbolInfo
{
public:
	LateSymbolInfo();
	~LateSymbolInfo();

	void loadMinidump(std::wstring &dumppath, bool delete_when_done);
	void unloadMinidump();

	void filterSymbol(Database::Address address, std::wstring &module, std::wstring &procname, std::wstring &sourcefile, unsigned &sourceline);

private:
	static wchar_t buffer[4096];
	std::wstring file_to_delete;

	// Dbgeng COM objects for minidump symbols
	struct IDebugClient5  *debugClient5;
	struct IDebugControl4 *debugControl4;
	struct IDebugSymbols3 *debugSymbols3;


};

void comenforce(HRESULT result, const char* where = NULL)
{
	if (result == S_OK)
		return;

	std::wostringstream message;
	if (where)
		message << where;

//	_com_error error(result);
//	message << ": " << error.ErrorMessage();
//	message << " (error " << result << ")";

	throw SleepyException(message.str());
}


LateSymbolInfo::LateSymbolInfo()
	:	debugClient5(NULL), debugControl4(NULL), debugSymbols3(NULL)
{
}

LateSymbolInfo::~LateSymbolInfo()
{
	unloadMinidump();
}

// Send debugger output to the wxWidgets current logging facility.
// The UI implements a logging facility in the form of a log panel.
struct DebugOutputCallbacksWide : public IDebugOutputCallbacksWide
{
	HRESULT	STDMETHODCALLTYPE QueryInterface(__in REFIID WXUNUSED(InterfaceId), __out PVOID* WXUNUSED(Interface)) { return E_NOINTERFACE; }
	ULONG	STDMETHODCALLTYPE AddRef() { return 1; }
	ULONG	STDMETHODCALLTYPE Release() { return 0; }

	HRESULT	STDMETHODCALLTYPE Output(__in ULONG WXUNUSED(Mask), __in PCWSTR Text)
	{
		//OutputDebugStringW(Text);
		wxLogMessage(L"%s", Text);
		return S_OK;
	}
};

static DebugOutputCallbacksWide *debugOutputCallbacks = new DebugOutputCallbacksWide();

void LateSymbolInfo::loadMinidump(std::wstring& dumppath, bool delete_when_done)
{
	// Method credit to http://stackoverflow.com/a/8119364/21501

	if (debugClient5 || debugControl4 || debugSymbols3)
	{
		//throw SleepyException(L"Minidump symbols already loaded.");

		// maybe the user moved a .pdb to somewhere where we can now find it?
		unloadMinidump();
	}

	IDebugClient *debugClient = NULL;

	SetLastError(0);
	comenforce(DebugCreate(__uuidof(IDebugClient), (void**)&debugClient), "DebugCreate");
	comenforce(debugClient->QueryInterface(__uuidof(IDebugClient5 ), (void**)&debugClient5 ), "QueryInterface(IDebugClient5)" );
	comenforce(debugClient->QueryInterface(__uuidof(IDebugControl4), (void**)&debugControl4), "QueryInterface(IDebugControl4)");
	comenforce(debugClient->QueryInterface(__uuidof(IDebugSymbols3), (void**)&debugSymbols3), "QueryInterface(IDebugSymbols3)");
	comenforce(debugClient5->SetOutputCallbacksWide(debugOutputCallbacks), "IDebugClient5::SetOutputCallbacksWide");
	comenforce(debugSymbols3->SetSymbolOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_OMAP_FIND_NEAREST | SYMOPT_AUTO_PUBLICS | SYMOPT_DEBUG), "IDebugSymbols::SetSymbolOptions");

	std::wstring sympath;
	//tanjl: TODO
//	prefs.AdjustSymbolPath(sympath, true);

	comenforce(debugSymbols3->SetSymbolPathWide(sympath.c_str()), "IDebugSymbols::SetSymbolPath");
	comenforce(debugClient5->OpenDumpFileWide(dumppath.c_str(), NULL), "IDebugClient4::OpenDumpFileWide");
	comenforce(debugControl4->WaitForEvent(0, INFINITE), "IDebugControl::WaitForEvent");

	// Since we can't just enumerate all symbols in all modules referenced by the minidump,
	// we have to keep the debugger session open and query symbols as requested by the
	// profiler GUI.

	debugClient->Release(); // but keep the other ones

	// If we are given a temporary file, clean it up later
	if (delete_when_done)
		file_to_delete = dumppath;
}

void LateSymbolInfo::unloadMinidump()
{
	if (debugClient5)
	{
		debugClient5->EndSession(DEBUG_END_ACTIVE_TERMINATE);
		debugClient5->Release();
		debugClient5 = NULL;
	}
	if (debugControl4)
	{
		debugControl4->Release();
		debugControl4 = NULL;
	}
	if (debugSymbols3)
	{
		debugSymbols3->Release();
		debugSymbols3 = NULL;
	}

	if (!file_to_delete.empty())
	{
		wxRemoveFile(file_to_delete);
		file_to_delete.clear();
	}
}

wchar_t LateSymbolInfo::buffer[4096];

void LateSymbolInfo::filterSymbol(Database::Address address, std::wstring &module, std::wstring &procname, std::wstring &sourcefile, unsigned &sourceline)
{
	if (debugSymbols3)
	{
		ULONG moduleindex;
		if (debugSymbols3->GetModuleByOffset(address, 0, &moduleindex, NULL) == S_OK)
			if (debugSymbols3->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, moduleindex, 0, buffer, _countof(buffer), NULL) == S_OK)
				module = buffer;

		if (debugSymbols3->GetNameByOffsetWide(address, buffer, _countof(buffer), NULL, NULL) == S_OK)
		{
			if (module.compare(buffer) != 0)
			{
				procname = buffer;

				// Remove redundant "Module!" prefix
				size_t modlength = module.length();
				if (procname.length() > modlength+1 && module.compare(0, modlength, procname, 0, modlength)==0 && procname[modlength] == '!')
					procname.erase(0, modlength+1);
			}
		}

		ULONG line;
		if (debugSymbols3->GetLineByOffsetWide(address, &line, buffer, _countof(buffer), NULL, NULL) == S_OK)
		{
			sourcefile = buffer;
			sourceline = line;
		}
	}
}

StringSet osModules(L"osmodules.txt",false);
StringSet osFunctions(L"osfunctions.txt",true);
Database *theDatabase;

Database::Database()
{
	assert(!theDatabase);
	theDatabase = this;
	late_sym_info = new LateSymbolInfo();
}

Database::~Database()
{
	clear();
	delete late_sym_info;
}

void Database::clear()
{
	for (auto i = symbols.begin(); i != symbols.end(); ++i)
		if (*i)
			delete *i;

	symbols.clear();
	files.clear();
	filemap.clear();
	addrinfo.clear();
	callstacks.clear();
	mainList.items.clear();
	mainList.totalcount = 0;
	has_minidump = false;
}

void Database::loadFromPath(const std::wstring& _profilepath, bool collapseOSCalls, bool loadMinidump)
{
	if(_profilepath != profilepath)
		profilepath = _profilepath;
	clear();

	wxFFileInputStream input(profilepath);
//	enforce(input.IsOk(), "Input stream error opening profile data.");

	// Check the version number required.
	{
		wxZipInputStream zipver(input);
//		enforce(zipver.IsOk(), "ZIP error opening profile data.");

		bool versionFound = false;
		while (wxZipEntry *entry = zipver.GetNextEntry())
		{
			wxString name = entry->GetInternalName();

			if (name.Left(8) == "Version " && name.Right(9) == " required")
			{
				versionFound = true;
				wxString ver = name.Mid(8, name.Length()-(8+9));
//				enforce(ver == FORMAT_VERSION, wxString::Format("Cannot load capture file: %s", name.c_str()).c_str());
			}
		}

//		enforce(versionFound, "Unrecognized capture file");
	}

	wxZipInputStream zip(input);
//	enforce(zip.IsOk(), "ZIP error opening profile data.");

	while (wxZipEntry *entry = zip.GetNextEntry())
	{
		wxString name = entry->GetInternalName();

			 if (name == "Symbols.txt")		loadSymbols(zip);
		else if (name == "Callstacks.txt")	loadCallstacks(zip,collapseOSCalls);
		else if (name == "IPCounts.txt")	loadIpCounts(zip);
		else if (name == "Stats.txt")		loadStats(zip);
		else if (name == "minidump.dmp")	{ has_minidump = true; if(loadMinidump) this->loadMinidump(zip); }
		else if (name.Left(8) == "Version ") {}
		else
			wxLogWarning("Other fluff found in capture file (%s)\n", name.c_str());
	}

//	setRoot(NULL);
}

#include "utils/except.h"
void Database::loadMinidump(wxInputStream &file)
{
	wxFFile minidump_file;
	std::wstring dumppath = wxFileName::CreateTempFileName(wxEmptyString, &minidump_file);
	wxFFileOutputStream minidump_stream(minidump_file);
	minidump_stream.Write(file);
	minidump_stream.Close();
	minidump_file.Close();

	try
	{
		late_sym_info->loadMinidump(dumppath, true);
	}
	catch (SleepyException &e)
	{
		wxLogError("%ls\n", e.wwhat());
		// Continue loading database
	}
}

void Database::loadStats(wxInputStream &file)
{
	wxTextInputStream str(file);

	stats.clear();

	while(!file.Eof())
	{
		wxString line = str.ReadLine();
		if (line.IsEmpty())
			break;

		stats.push_back(line.c_str().AsWChar());
	}
}

void Database::loadIpCounts(wxInputStream &file)
{
	double totalcount = 0;
	wxTextInputStream str(file);

	str >> totalcount;

	while(!file.Eof())
	{
		wxString line = str.ReadLine();
		if (line.IsEmpty())
			break;

		std::wistringstream stream(line.c_str().AsWChar());

		std::wstring addrstr;
		double count;

		stream >> addrstr;
		stream >> count;

		Address addr = hexStringTo64UInt(addrstr);
		AddrInfo *info = &addrinfo.at(addr);
		info->count += count;
		info->percentage += 100.0f * ((float)count / (float)totalcount);
	}
}

void Database::loadCallstacks(wxInputStream &file,bool collapseKernelCalls)
{
	wxTextInputStream str(file);

	size_t filesize = file.GetSize();
//	wxProgressDialog progressdlg(APPNAME, "Loading callstacks...",
//		kMaxProgress, theMainWin,
//		wxPD_APP_MODAL|wxPD_AUTO_HIDE);

	while (!file.Eof())
	{
		wxString line = str.ReadLine();
		if (line.IsEmpty())
			break;

		std::wistringstream stream(line.c_str().AsWChar());

		CallStack callstack;
		stream >> callstack.samplecount;

		while (true)
		{
			std::wstring addrstr;
			stream >> addrstr;
			if (addrstr.empty())
				break;
			Address addr = hexStringTo64UInt(addrstr);

			if (collapseKernelCalls && addrinfo.at(addr).symbol->isCollapseFunction)
				callstack.addresses.clear();

			callstack.addresses.push_back(addr);
		}

		if (collapseKernelCalls)
		{
			if (callstack.addresses.size() >= 2 && addrinfo.at(callstack.addresses[0]).symbol->isCollapseModule)
			{
				do
				{
					if (!addrinfo.at(callstack.addresses[1]).symbol->isCollapseModule)
						break;
					callstack.addresses.erase(callstack.addresses.begin());
				}
				while (callstack.addresses.size() >= 2);
			}
		}

		callstack.symbols.resize(callstack.addresses.size());
		for (size_t i=0; i<callstack.addresses.size(); i++)
			callstack.symbols[i] = addrinfo.at(callstack.addresses[i]).symbol;

		callstacks.emplace_back(std::move(callstack));

		wxFileOffset offset = file.TellI();
//		if (offset != wxInvalidOffset && offset != (wxFileOffset)filesize)
//			progressdlg.Update(kMaxProgress * offset / filesize);
	}

	struct Pred
	{
		bool operator () (const CallStack &a, const CallStack &b)
		{
			long l = a.addresses.size() - b.addresses.size();
			return l ? l<0 : a.addresses < b.addresses;
		}
	};

	// Sort and filter repeating callstacks
	{
//		progressdlg.Update(0, "Sorting...");
//		progressdlg.Pulse();

		std::stable_sort(callstacks.begin(), callstacks.end(), Pred());

//		progressdlg.Update(0, "Filtering...");

		std::vector<CallStack> filtered;
		const auto total = callstacks.size();
		for (size_t i = 0; i < total; ++i)
		{
//			if (i % 256 == 0)
//				progressdlg.Update(kMaxProgress * i / total);

			auto& item = callstacks[i];
			if (!filtered.empty() && filtered.back().addresses == item.addresses)
				filtered.back().samplecount += item.samplecount;
			else
				filtered.emplace_back(std::move(item));
		}

		std::swap(filtered, callstacks);
	}
}

void Database::loadSymbols(wxInputStream &file)
{
	wxTextInputStream str(file, wxT(" \t"), wxConvAuto(wxFONTENCODING_UTF8));

	size_t filesize = file.GetSize();
//	wxProgressDialog progressdlg(APPNAME, "Loading symbols...",
//		kMaxProgress+1, theMainWin,
//		wxPD_APP_MODAL|wxPD_AUTO_HIDE);

	std::unordered_map<std::wstring, const Symbol*> locsymbols;

	bool warnedDupAddress = false;
	while (!file.Eof())
	{
		wxString line = str.ReadLine();
		if (line.IsEmpty())
			break;

		std::wistringstream stream(line.c_str().AsWChar());

		std::wstring addrstr;
		stream >> addrstr;
		Address addr = hexStringTo64UInt(addrstr);

		std::wstring sourcefilename, modulename, procname;

		bool inserted;
		AddrInfo &info = map_emplace(addrinfo, addr, &inserted);
		::readQuote(stream, modulename);
		::readQuote(stream, procname);
		::readQuote(stream, sourcefilename);
		stream >> info.sourceline;
		if (!inserted)
		{
			if (!warnedDupAddress)
				wxLogWarning("Duplicate address in symbol list:\nAddress: " + addrstr + "\nSymbol: " + procname);
			warnedDupAddress = true;
			continue;
		}
		enforce(stream.eof(), "Trailing data in line: " + line);

		// Late symbol lookup
		late_sym_info->filterSymbol(addr, modulename, procname, sourcefilename, info.sourceline);

		// Convert filename and module strings to a numeric IDs
		FileID   fileid   = map_string(files  , filemap  , sourcefilename);
		ModuleID moduleid = map_string(modules, modulemap, modulename    );

		// Build a key string for grouping addresses belonging to the same symbol
		std::wostringstream locstream;
		locstream << modulename << '/' << sourcefilename << '/' << procname;
		std::wstring loc = locstream.str();

		// Create a new symbol entry, or lookup the existing one, based on the key
		const Symbol *&sym = map_emplace(locsymbols, loc, &inserted);
		if (inserted) // new symbol, judging by its location?
		{
			Symbol *newsym = new Symbol;
			newsym->id                 = symbols.size();
			newsym->address            = addr;
			newsym->procname           = procname;
			newsym->sourcefile         = fileid;
			newsym->module             = moduleid;
			newsym->isCollapseFunction = osFunctions.Contains(procname  .c_str());
			newsym->isCollapseModule   = osModules  .Contains(modulename.c_str());
			symbols.push_back(newsym);
			sym = newsym;
		}

		info.symbol = sym;

		wxFileOffset offset = file.TellI();
//		if (offset != wxInvalidOffset && offset != (wxFileOffset)filesize)
//			progressdlg.Update(kMaxProgress * offset / filesize);
	}

	// The unordered_map destructor takes a very long time to run.
//	progressdlg.Update(kMaxProgress, "Tidying things up...");
}

void LoadProfileData(const std::wstring &filename)
{
	Database *database = new Database();
	database->loadFromPath(filename, false, false);
}
int _tmain(int argc, _TCHAR* argv[])
{
	if (!dbgHelpInit())
	{
		abort();
		return -1;
	}
	DWORD processId = 1556;
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
	//profilerthread->cancel();
	profilerthread->commit_suicide = true;
	std::wstring ws = profilerthread->getFilename();
	std::string s( ws.begin(), ws.end() );
	printf("file name:%s\n", s.c_str());
	system("pause");
	LoadProfileData(ws);
	system("pause");
	return 0;
}

