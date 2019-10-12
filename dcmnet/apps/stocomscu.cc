/*
 *
 *  Copyright (C) 2019.
 *  All rights reserved.  See COPYRIGHT file for details.
 *
 *  Module:  dcmnet
 *
 *  Author:  Xi Kuibin
 *
 *  Purpose: Storage Commitments Service Class User
 *
 */

#include "dcmtk/config/osconfig.h" /* make sure OS specific configuration is included first */

#define INCLUDE_CSTDLIB
#define INCLUDE_CSTDIO
#define INCLUDE_CSTRING
#define INCLUDE_CCTYPE
#include "dcmtk/ofstd/ofstdinc.h"

BEGIN_EXTERN_C
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
END_EXTERN_C

#include "dcmtk/ofstd/ofstd.h"
#include "dcmtk/ofstd/ofconapp.h"
#include "dcmtk/ofstd/ofstring.h"
#include "dcmtk/ofstd/ofstream.h"
#include "dcmtk/dcmnet/dicom.h"      /* for DICOM_APPLICATION_REQUESTOR */
#include "dcmtk/dcmnet/dimse.h"
#include "dcmtk/dcmnet/diutil.h"
#include "dcmtk/dcmnet/dcmtrans.h"   /* for dcmSocketSend/ReceiveTimeout */
#include "dcmtk/dcmnet/dcasccfg.h"   /* for class DcmAssociationConfiguration */
#include "dcmtk/dcmnet/dcasccff.h"   /* for class DcmAssociationConfigurationFile */
#include "dcmtk/dcmdata/dcdatset.h"
#include "dcmtk/dcmdata/dcmetinf.h"
#include "dcmtk/dcmdata/dcfilefo.h"
#include "dcmtk/dcmdata/dcuid.h"
#include "dcmtk/dcmdata/dcdict.h"
#include "dcmtk/dcmdata/dcdeftag.h"
#include "dcmtk/dcmdata/cmdlnarg.h"
#include "dcmtk/dcmdata/dcuid.h"     /* for dcmtk version name */
#include "dcmtk/dcmdata/dcostrmz.h"  /* for dcmZlibCompressionLevel */
#include "dcmtk/dcmtls/tlsopt.h"      /* for DcmTLSOptions */


#if defined (HAVE_WINDOWS_H) || defined(HAVE_FNMATCH_H)
#define PATTERN_MATCHING_AVAILABLE
#endif

#define OFFIS_CONSOLE_APPLICATION "stocomscu"

static OFLogger stocomscuLogger = OFLog::getLogger("dcmtk.apps." OFFIS_CONSOLE_APPLICATION);

static char rcsid[] = "$dcmtk: " OFFIS_CONSOLE_APPLICATION " v"
OFFIS_DCMTK_VERSION " 2019-10-15 $";

/* default application titles */
#define APPLICATIONTITLE     "STORE-COM-SCU"
#define PEERAPPLICATIONTITLE "STORE-COM-SCP"

static OFBool opt_showPresentationContexts = OFFalse;
static OFBool opt_abortAssociation = OFFalse;
static OFCmdUnsignedInt opt_maxReceivePDULength = ASC_DEFAULTMAXPDU;
static OFCmdUnsignedInt opt_maxSendPDULength = 0;
static E_TransferSyntax opt_networkTransferSyntax = EXS_Unknown;
static E_FileReadMode opt_readMode = ERM_autoDetect;
OFCmdUnsignedInt   opt_port = 0;

static OFBool opt_scanDir = OFFalse;
static OFBool opt_recurse = OFFalse;
static const char *opt_scanPattern = "";

static OFBool opt_haltOnUnsuccessfulStore = OFTrue;
static OFBool unsuccessfulStoreEncountered = OFFalse;
static int lastStatusCode = STATUS_Success;

static OFCmdUnsignedInt opt_repeatCount = 1;

static OFBool opt_correctUIDPadding = OFFalse;

static const char *opt_configFile = NULL;
static const char *opt_profileName = NULL;
T_DIMSE_BlockingMode opt_blockMode = DIMSE_BLOCKING;
int opt_dimse_timeout = 0;
int opt_acse_timeout = 30;
OFCmdSignedInt opt_socket_timeout = 60;
OFBool opt_promiscuous = OFFalse;
const char *opt_peer = NULL;
OFCmdUnsignedInt opt_peerport = 104;
const char *opt_peerTitle = PEERAPPLICATIONTITLE;
const char *opt_ourTitle = APPLICATIONTITLE;

OFBool             opt_acceptAllXfers = OFFalse;
OFBool             opt_refuseAssociation = OFFalse;
OFBool             opt_rejectWithoutImplementationUID = OFFalse;
OFString           callingAETitle;                    // calling application entity title will be stored here
OFString           lastCallingAETitle;
OFString           calledAETitle;                     // called application entity title will be stored here
OFString           lastCalledAETitle;
OFString           callingPresentationAddress;        // remote hostname or IP address will be stored here
OFString           lastCallingPresentationAddress;
const char *       opt_respondingAETitle = APPLICATIONTITLE;

static OFCondition
addStorageCommPresentationContexts(T_ASC_Parameters *params);

static OFCondition
storecommSCU(T_ASC_Association *assoc, const OFList<OFString>& sopClassUIDList,
	const OFList<OFString>& sopInstanceUIDList);

static OFBool
findSOPClassAndInstanceInFile(
	const char *fname,
	char *sopClass,
	size_t sopClassSize,
	char *sopInstance,
	size_t sopInstanceSize);

int actionRequest(int argc, char *argv[]);

int handleEventReport(int argc, char *argv[]);

void PrepareCommandOptions(OFCommandLine &cmd);
int CheckCommandOptions(OFConsoleApplication &app, OFCommandLine &cmd, int argc, char ** argv, DcmTLSOptions &tlsOptions);

static OFCondition processCommands(T_ASC_Association *assoc);
static OFCondition acceptAssociation(T_ASC_Network *net, DcmAssociationConfiguration& asccfg, OFBool secureConnection);
static OFCondition echoSCP(T_ASC_Association * assoc, T_DIMSE_Message * msg, T_ASC_PresentationContextID presID);
static OFCondition eventReportSCP(T_ASC_Association * assoc, T_DIMSE_Message * msg, T_ASC_PresentationContextID presID);
static void executeCommand(const OFString &cmd);

static OFCondition acceptUnknownContextsWithPreferredTransferSyntaxes(
	T_ASC_Parameters * params,
	const char* transferSyntaxes[],
	int transferSyntaxCount,
	T_ASC_SC_ROLE acceptedRole = ASC_SC_ROLE_DEFAULT);


/* helper macro for converting stream output to a string */
#define CONVERT_TO_STRING(output, string) \
    optStream.str(""); \
    optStream.clear(); \
    optStream << output << OFStringStream_ends; \
    OFSTRINGSTREAM_GETOFSTRING(optStream, string)

#define SHORTCOL 4
#define LONGCOL 19

int main(int argc, char *argv[])
{
	OFLOG_INFO(stocomscuLogger, "--Start sending N-Action request--");
	int exitcode = actionRequest(argc, argv);
	OFLOG_INFO(stocomscuLogger, "--End of N-Action request--");

	if (exitcode == 0)
	{
		OFLOG_INFO(stocomscuLogger, "--Start a new association to receive N-Event-Report--");
		exitcode = handleEventReport(argc, argv);
		OFLOG_INFO(stocomscuLogger, "--End of handling  N-Event-Report request--");
	}

#ifdef DEBUG
	dcmDataDict.clear();  /* useful for debugging with dmalloc */
#endif
	return exitcode;
}


int handleEventReport(int argc, char *argv[])
{
	T_ASC_Network *net;
	DcmAssociationConfiguration asccfg;
	DcmTLSOptions tlsOptions(NET_ACCEPTOR);

	OFStandard::initializeNetwork();
#ifdef WITH_OPENSSL
	DcmTLSTransportLayer::initializeOpenSSL();
#endif

	OFString temp_str;
	OFOStringStream optStream;

	OFConsoleApplication app(OFFIS_CONSOLE_APPLICATION, "DICOM N-EVENT-REPORT SCP", rcsid);
	OFCommandLine cmd;

	PrepareCommandOptions(cmd);

	// add TLS specific command line options if (and only if) we are compiling with OpenSSL
	tlsOptions.addTLSCommandlineOptions(cmd);

	/* evaluate command line */
	prepareCmdLineArgs(argc, argv, OFFIS_CONSOLE_APPLICATION);
	
	//CheckEventSCPOptions(app, cmd, argc, argv, tlsOptions);
	CheckCommandOptions(app, cmd, argc, argv, tlsOptions);

	// evaluate (most of) the TLS command line options (if we are compiling with OpenSSL)
	tlsOptions.parseArguments(app, cmd);

#ifndef DISABLE_PORT_PERMISSION_CHECK
#ifdef HAVE_GETEUID
	/* if port is privileged we must be as well */
	if (opt_port < 1024)
	{
		if (geteuid() != 0)
		{
			OFLOG_FATAL(stocomscuLogger, "cannot listen on port " << opt_port << ", insufficient privileges");
			return 1;
		}
	}
#endif
#endif

	/* make sure data dictionary is loaded */
	if (!dcmDataDict.isDictionaryLoaded())
	{
		OFLOG_WARN(stocomscuLogger, "no data dictionary loaded, check environment variable: "
			<< DCM_DICT_ENVIRONMENT_VARIABLE);
	}



	/* initialize network, i.e. create an instance of T_ASC_Network*. */
	OFCondition cond = ASC_initializeNetwork(NET_ACCEPTOR, OFstatic_cast(int, opt_port), opt_acse_timeout, &net);
	if (cond.bad())
	{
		OFLOG_ERROR(stocomscuLogger, "cannot create network: " << DimseCondition::dump(temp_str, cond));
		return 1;
	}

	/* drop root privileges now and revert to the calling user id (if we are running as setuid root) */
	if (OFStandard::dropPrivileges().bad())
	{
		OFLOG_FATAL(stocomscuLogger, "setuid() failed, maximum number of processes/threads for uid already running.");
		return 1;
	}

	/* create a secure transport layer if requested and OpenSSL is available */
	cond = tlsOptions.createTransportLayer(net, NULL, app, cmd);
	if (cond.bad()) {
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		exit(1);
	}


	while (cond.good())
	{
		/* receive an association and acknowledge or reject it. If the association was */
		/* acknowledged, offer corresponding services and invoke one or more if required. */
		cond = acceptAssociation(net, asccfg, tlsOptions.secureConnectionRequested());

		/* since storescp is usually terminated with SIGTERM or the like,
		* we write back an updated random seed after every association handled.
		*/
		cond = tlsOptions.writeRandomSeed();
		if (cond.bad()) {
			// failure to write back the random seed is a warning, not an error
			OFLOG_WARN(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		}

		// if running in inetd mode, we always terminate after one association
		OFBool breakAfterOneReportAssc = OFTrue;
		if (breakAfterOneReportAssc) break;

	}

	/* drop the network, i.e. free memory of T_ASC_Network* structure. This call */
	/* is the counterpart of ASC_initializeNetwork(...) which was called above. */
	cond = ASC_dropNetwork(&net);
	if (cond.bad())
	{
		OFLOG_ERROR(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		return 1;
	}

	OFStandard::shutdownNetwork();
	return 0;

}

void PrepareCommandOptions(OFCommandLine &cmd)
{
	OFOStringStream optStream;
	cmd.setParamColumn(LONGCOL + SHORTCOL + 4);
	cmd.addParam("peer", "hostname of DICOM peer");
	cmd.addParam("port", "tcp/ip port number of peer");
	cmd.addParam("dcmfile-in", "DICOM file or directory to be queried", OFCmdParam::PM_MultiMandatory);

	cmd.setOptionColumns(LONGCOL, SHORTCOL);
	cmd.addGroup("general options:", LONGCOL, SHORTCOL + 2);
	cmd.addOption("--help", "-h", "print this help text and exit", OFCommandLine::AF_Exclusive);
	cmd.addOption("--version", "print version information and exit", OFCommandLine::AF_Exclusive);
	OFLog::addOptions(cmd);
	cmd.addOption("--verbose-pc", "+v", "show presentation contexts in verbose mode");

	cmd.addGroup("input options:");
	cmd.addSubGroup("input files:");
	cmd.addOption("--scan-directories", "+sd", "scan directories for input files (dcmfile-in)");
#ifdef PATTERN_MATCHING_AVAILABLE
	cmd.addOption("--scan-pattern", "+sp", 1, "[p]attern: string (only with --scan-directories)",
		"pattern for filename matching (wildcards)");
#endif
	cmd.addOption("--no-recurse", "-r", "do not recurse within directories (default)");
	cmd.addOption("--recurse", "+r", "recurse within specified directories");
	cmd.addGroup("network options:");

	cmd.addSubGroup("application entity titles:");
	cmd.addOption("--aetitle", "-aet", 1, "[a]etitle: string", "set my calling AE title (default: " APPLICATIONTITLE ")");
	cmd.addOption("--call", "-aec", 1, "[a]etitle: string", "set called AE title of peer (default: " PEERAPPLICATIONTITLE ")");

	cmd.addSubGroup("port for incoming network associations:");
	cmd.addOption("--no-port", "no port for incoming associations (default)");
	cmd.addOption("--port", "+P", 1, "[n]umber: integer",
		"port number for incoming associations");
	cmd.addSubGroup("other network options:");
	cmd.addOption("--timeout", "-to", 1, "[s]econds: integer (default: unlimited)", "timeout for connection requests");
	CONVERT_TO_STRING("[s]econds: integer (default: " << opt_socket_timeout << ")", optString1);
	cmd.addOption("--socket-timeout", "-ts", 1, optString1.c_str(), "timeout for network socket (0 for none)");
	CONVERT_TO_STRING("[s]econds: integer (default: " << opt_acse_timeout << ")", optString2);
	cmd.addOption("--acse-timeout", "-ta", 1, optString2.c_str(), "timeout for ACSE messages");
	cmd.addOption("--dimse-timeout", "-td", 1, "[s]econds: integer (default: unlimited)", "timeout for DIMSE messages");

	CONVERT_TO_STRING("[n]umber of bytes: integer (" << ASC_MINIMUMPDUSIZE << ".." << ASC_MAXIMUMPDUSIZE << ")", optString3);
	CONVERT_TO_STRING("set max receive pdu to n bytes (default: " << opt_maxReceivePDULength << ")", optString4);
	cmd.addOption("--max-recv-pdu", "-pdu", 1, optString3.c_str(), optString4.c_str());
	cmd.addOption("--max-send-pdu", 1, optString3.c_str(), "restrict max send pdu to n bytes");


	cmd.addOption("--repeat", 1, "[n]umber: integer", "repeat n times");
	cmd.addOption("--abort", "abort association instead of releasing it");
	cmd.addOption("--no-halt", "-nh", "do not halt if unsuccessful store encountered\n(default: do halt)");
	cmd.addOption("--uid-padding", "-up", "silently correct space-padded UIDs");

	cmd.addOption("--disable-host-lookup", "-dhl", "disable hostname lookup");
	cmd.addOption("--refuse", "refuse association");
	cmd.addOption("--reject", "reject association if no implement. class UID");

	cmd.addOption("--promiscuous", "-pm", "promiscuous mode, accept unknown SOP classes\n(not with --config-file)");
}

int CheckCommandOptions(OFConsoleApplication &app, OFCommandLine &cmd, int argc, char ** argv, DcmTLSOptions &tlsOptions)
{
	if (app.parseCommandLine(cmd, argc, argv))
	{
		/* check exclusive options first */
		if (cmd.hasExclusiveOption())
		{
			if (cmd.findOption("--version"))
			{
				app.printHeader(OFTrue /*print host identifier*/);
				COUT << OFendl << "External libraries used:";
#if !defined(WITH_ZLIB) && !defined(WITH_OPENSSL) && !defined(WITH_TCPWRAPPER)
				COUT << " none" << OFendl;
#else
				COUT << OFendl;
#endif

				// print OpenSSL version if (and only if) we are compiling with OpenSSL
				tlsOptions.printLibraryVersion();
#ifdef WITH_TCPWRAPPER
				COUT << "- LIBWRAP" << OFendl;
#endif
				return 0;
			}

			// check if the command line contains the --list-ciphers option
			if (tlsOptions.listOfCiphersRequested(cmd))
			{
				tlsOptions.printSupportedCiphersuites(app, COUT);
				return 0;
			}
		}

		/* command line parameters */

		cmd.getParam(1, opt_peer);
		app.checkParam(cmd.getParamAndCheckMinMax(2, opt_peerport, 1, 65535));

		OFLog::configureFromCommandLine(cmd, app);
		if (cmd.findOption("--verbose-pc"))
		{
			app.checkDependence("--verbose-pc", "verbose mode", stocomscuLogger.isEnabledFor(OFLogger::INFO_LOG_LEVEL));
			opt_showPresentationContexts = OFTrue;
		}

		if (cmd.findOption("--scan-directories")) opt_scanDir = OFTrue;

#ifdef PATTERN_MATCHING_AVAILABLE
		if (cmd.findOption("--scan-pattern"))
		{
			app.checkDependence("--scan-pattern", "--scan-directories", opt_scanDir);
			app.checkValue(cmd.getValue(opt_scanPattern));
		}
#endif

		cmd.beginOptionBlock();
		if (cmd.findOption("--no-recurse")) opt_recurse = OFFalse;
		if (cmd.findOption("--recurse"))
		{
			app.checkDependence("--recurse", "--scan-directories", opt_scanDir);
			opt_recurse = OFTrue;
		}
		cmd.endOptionBlock();

		if (cmd.findOption("--aetitle")) app.checkValue(cmd.getValue(opt_ourTitle));
		if (cmd.findOption("--call")) app.checkValue(cmd.getValue(opt_peerTitle));

		cmd.beginOptionBlock();
		if (cmd.findOption("--port"))    app.checkValue(cmd.getValueAndCheckMinMax(opt_port, 1, 65535));
		if (cmd.findOption("--no-port")) opt_port = 0;
		cmd.endOptionBlock();

		app.checkValue(cmd.getValue(opt_profileName));

	}

	if (cmd.findOption("--timeout"))
	{
		OFCmdSignedInt opt_timeout = 0;
		app.checkValue(cmd.getValueAndCheckMin(opt_timeout, 1));
		dcmConnectionTimeout.set(OFstatic_cast(Sint32, opt_timeout));
	}

	if (cmd.findOption("--socket-timeout"))
		app.checkValue(cmd.getValueAndCheckMin(opt_socket_timeout, -1));
	// always set the timeout values since the global default might be different
	dcmSocketSendTimeout.set(OFstatic_cast(Sint32, opt_socket_timeout));
	dcmSocketReceiveTimeout.set(OFstatic_cast(Sint32, opt_socket_timeout));

	if (cmd.findOption("--acse-timeout"))
	{
		OFCmdSignedInt opt_timeout = 0;
		app.checkValue(cmd.getValueAndCheckMin(opt_timeout, 1));
		opt_acse_timeout = OFstatic_cast(int, opt_timeout);
	}

	if (cmd.findOption("--dimse-timeout"))
	{
		OFCmdSignedInt opt_timeout = 0;
		app.checkValue(cmd.getValueAndCheckMin(opt_timeout, 1));
		opt_dimse_timeout = OFstatic_cast(int, opt_timeout);
		opt_blockMode = DIMSE_NONBLOCKING;
	}

	if (cmd.findOption("--max-recv-pdu"))
		app.checkValue(cmd.getValueAndCheckMinMax(opt_maxReceivePDULength, ASC_MINIMUMPDUSIZE, ASC_MAXIMUMPDUSIZE));

	if (cmd.findOption("--max-send-pdu"))
	{
		app.checkValue(cmd.getValueAndCheckMinMax(opt_maxSendPDULength, ASC_MINIMUMPDUSIZE, ASC_MAXIMUMPDUSIZE));
		dcmMaxOutgoingPDUSize.set(OFstatic_cast(Uint32, opt_maxSendPDULength));
	}

	if (cmd.findOption("--repeat"))  app.checkValue(cmd.getValueAndCheckMin(opt_repeatCount, 1));
	if (cmd.findOption("--abort"))   opt_abortAssociation = OFTrue;
	if (cmd.findOption("--no-halt")) opt_haltOnUnsuccessfulStore = OFFalse;
	if (cmd.findOption("--uid-padding")) opt_correctUIDPadding = OFTrue;

	if (cmd.findOption("--disable-host-lookup")) dcmDisableGethostbyaddr.set(OFTrue);
	if (cmd.findOption("--refuse")) opt_refuseAssociation = OFTrue;
	if (cmd.findOption("--reject")) opt_rejectWithoutImplementationUID = OFTrue;
	if (cmd.findOption("--promiscuous")) opt_promiscuous = OFTrue;

	// evaluate (most of) the TLS command line options (if we are compiling with OpenSSL)
	tlsOptions.parseArguments(app, cmd);

	return 0;
}

int actionRequest(int argc, char *argv[])
{
	OFOStringStream optStream;

	OFList<OFString> fileNameList;       // list of files to transfer to SCP
	OFList<OFString> sopClassUIDList;    // the list of SOP classes
	OFList<OFString> sopInstanceUIDList; // the list of SOP instances

	T_ASC_Network *net;
	T_ASC_Parameters *params;
	DIC_NODENAME peerHost;
	T_ASC_Association *assoc;
	DcmAssociationConfiguration asccfg;  // handler for association configuration profiles
	DcmTLSOptions tlsOptions(NET_REQUESTOR);

	OFStandard::initializeNetwork();
	//#ifdef WITH_OPENSSL
	//  DcmTLSTransportLayer::initializeOpenSSL();
	//#endif
	//
	OFString temp_str;
	OFConsoleApplication app(OFFIS_CONSOLE_APPLICATION, "DICOM storage commitment SCU", rcsid);
	OFCommandLine cmd;

	PrepareCommandOptions(cmd);
	// add TLS specific command line options if (and only if) we are compiling with OpenSSL
	tlsOptions.addTLSCommandlineOptions(cmd);

	/* evaluate command line */
	prepareCmdLineArgs(argc, argv, OFFIS_CONSOLE_APPLICATION);
	CheckCommandOptions(app, cmd, argc, argv, tlsOptions);

  /* print resource identifier */
	OFLOG_DEBUG(stocomscuLogger, rcsid << OFendl);

	/* make sure data dictionary is loaded */
	if (!dcmDataDict.isDictionaryLoaded())
	{
		OFLOG_WARN(stocomscuLogger, "no data dictionary loaded, check environment variable: "
			<< DCM_DICT_ENVIRONMENT_VARIABLE);
	}

	/* finally, create list of input files */
	const char *paramString = NULL;
	const int paramCount = cmd.getParamCount();
	OFList<OFString> inputFiles;
	if (opt_scanDir)
		OFLOG_INFO(stocomscuLogger, "determining input files ...");
	/* iterate over all input filenames/directories */
	for (int i = 3; i <= paramCount; i++)
	{
		cmd.getParam(i, paramString);
		/* search directory recursively (if required) */
		if (OFStandard::dirExists(paramString))
		{
			if (opt_scanDir)
				OFStandard::searchDirectoryRecursively(paramString, inputFiles, opt_scanPattern, "" /*dirPrefix*/, opt_recurse);
			else
				OFLOG_WARN(stocomscuLogger, "ignoring directory because option --scan-directories is not set: " << paramString);
		}
		else
			inputFiles.push_back(paramString);
	}
	/* check whether there are any input files at all */
	if (inputFiles.empty())
	{
		OFLOG_FATAL(stocomscuLogger, "no input files to be sent");
		exit(1);
	}

	/* check input files */
	OFString errormsg;
	DcmFileFormat dfile;
	char sopClassUID[128];
	char sopInstanceUID[128];
	OFBool ignoreName;
	const char *currentFilename = NULL;
	OFListIterator(OFString) if_iter = inputFiles.begin();
	OFListIterator(OFString) if_last = inputFiles.end();
	OFLOG_INFO(stocomscuLogger, "checking input files ...");
	/* iterate over all input filenames */
	while (if_iter != if_last)
	{
		ignoreName = OFFalse;
		currentFilename = (*if_iter).c_str();
		if (OFStandard::fileExists(currentFilename))
		{
			OFLOG_DEBUG(stocomscuLogger, "in file " << currentFilename);
			
			if (!findSOPClassAndInstanceInFile(currentFilename, sopClassUID, sizeof(sopClassUID), sopInstanceUID, sizeof(sopInstanceUID)))
			{
				ignoreName = OFTrue;
				errormsg = "missing SOP class (or instance) in file: ";
				errormsg += currentFilename;
				if (opt_haltOnUnsuccessfulStore)
				{
					OFLOG_FATAL(stocomscuLogger, errormsg);
					exit(1);
				}
				else
					OFLOG_WARN(stocomscuLogger, errormsg << ", ignoring file");
			}
			else if (!dcmIsaStorageSOPClassUID(sopClassUID, ESSC_All))
			{
				ignoreName = OFTrue;
				errormsg = "unknown storage SOP class in file: ";
				errormsg += currentFilename;
				errormsg += ": ";
				errormsg += sopClassUID;
				if (opt_haltOnUnsuccessfulStore)
				{
					OFLOG_FATAL(stocomscuLogger, errormsg);
					exit(1);
				}
				else
					OFLOG_WARN(stocomscuLogger, errormsg << ", ignoring file");
			}
			else
			{
				OFLOG_TRACE(stocomscuLogger, "SOPClassUid: " << sopClassUID << "SOPInstanceUid: " << sopInstanceUID << "in file " << currentFilename);
				sopClassUIDList.push_back(sopClassUID);
				sopInstanceUIDList.push_back(sopInstanceUID);
			}
			
			if (!ignoreName) fileNameList.push_back(currentFilename);
		}
		else
		{
			errormsg = "cannot access file: ";
			errormsg += currentFilename;
			if (opt_haltOnUnsuccessfulStore)
			{
				OFLOG_FATAL(stocomscuLogger, errormsg);
				exit(1);
			}
			else
				OFLOG_WARN(stocomscuLogger, errormsg << ", ignoring file");
		}
		++if_iter;
	}

	if (sopClassUIDList.empty() || sopInstanceUIDList.empty())
	{
		OFLOG_ERROR(stocomscuLogger, "Not instance to be queried.");
		return 1;
	}

	/* initialize network, i.e. create an instance of T_ASC_Network*. */
	OFCondition cond = ASC_initializeNetwork(NET_REQUESTOR, 0, opt_acse_timeout, &net);
	if (cond.bad()) {
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		return 1;
	}

	/* initialize asscociation parameters, i.e. create an instance of T_ASC_Parameters*. */
	cond = ASC_createAssociationParameters(&params, opt_maxSendPDULength);
	if (cond.bad()) {
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		return 1;
	}

	/* create a secure transport layer if requested and OpenSSL is available */
	cond = tlsOptions.createTransportLayer(net, params, app, cmd);
	if (cond.bad()) {
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		return 1;
	}

	/* sets this application's title and the called application's title in the params */
	/* structure. The default values to be set here are "STORESCU" and "ANY-SCP". */
	ASC_setAPTitles(params, opt_ourTitle, opt_peerTitle, NULL);

	/* Figure out the presentation addresses and copy the */
	/* corresponding values into the association parameters.*/
	sprintf(peerHost, "%s:%d", opt_peer, OFstatic_cast(int, opt_peerport));
	ASC_setPresentationAddresses(params, OFStandard::getHostName().c_str(), peerHost);

	/* Set the presentation contexts which will be negotiated */
	/* when the network connection will be established */
	cond = addStorageCommPresentationContexts(params);

	if (cond.bad()) {
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		return 1;
	}

	/* dump presentation contexts if required */
	if (opt_showPresentationContexts)
		OFLOG_INFO(stocomscuLogger, "Request Parameters:" << OFendl << ASC_dumpParameters(temp_str, params, ASC_ASSOC_RQ));
	else
		OFLOG_DEBUG(stocomscuLogger, "Request Parameters:" << OFendl << ASC_dumpParameters(temp_str, params, ASC_ASSOC_RQ));

	/* create association, i.e. try to establish a network connection to another */
	/* DICOM application. This call creates an instance of T_ASC_Association*. */
	OFLOG_INFO(stocomscuLogger, "Requesting Association");
	cond = ASC_requestAssociation(net, params, &assoc);
	if (cond.bad()) {
		if (cond == DUL_ASSOCIATIONREJECTED) {
			T_ASC_RejectParameters rej;

			ASC_getRejectParameters(params, &rej);
			OFLOG_FATAL(stocomscuLogger, "Association Rejected:" << OFendl << ASC_printRejectParameters(temp_str, &rej));
			return 1;
		}
		else {
			OFLOG_FATAL(stocomscuLogger, "Association Request Failed: " << DimseCondition::dump(temp_str, cond));
			return 1;
		}
	}

	/* dump the connection parameters if in debug mode*/
	OFLOG_DEBUG(stocomscuLogger, ASC_dumpConnectionParameters(temp_str, assoc));

	/* dump the presentation contexts which have been accepted/refused */
	if (opt_showPresentationContexts)
		OFLOG_INFO(stocomscuLogger, "Association Parameters Negotiated:" << OFendl << ASC_dumpParameters(temp_str, params, ASC_ASSOC_AC));
	else
		OFLOG_DEBUG(stocomscuLogger, "Association Parameters Negotiated:" << OFendl << ASC_dumpParameters(temp_str, params, ASC_ASSOC_AC));

	/* count the presentation contexts which have been accepted by the SCP */
	/* If there are none, finish the execution */
	if (ASC_countAcceptedPresentationContexts(params) == 0) {
		OFLOG_FATAL(stocomscuLogger, "No Acceptable Presentation Contexts");
		return 1;
	}

	/* dump general information concerning the establishment of the network connection if required */
	OFLOG_INFO(stocomscuLogger, "Association Accepted (Max Send PDV: " << assoc->sendPDVLength << ")");

	OFLOG_INFO(stocomscuLogger, "Total " << sopInstanceUIDList.size() << " items to be committed.");
	cond = storecommSCU(assoc, sopClassUIDList, sopInstanceUIDList);


	/* tear down association, i.e. terminate network connection to SCP */
	if (cond == EC_Normal)
	{
		if (opt_abortAssociation) {
			OFLOG_INFO(stocomscuLogger, "Aborting Association");
			cond = ASC_abortAssociation(assoc);
			if (cond.bad()) {
				OFLOG_ERROR(stocomscuLogger, "Association Abort Failed: " << DimseCondition::dump(temp_str, cond));
				return 1;
			}
		}
		else {
			/* release association */
			OFLOG_INFO(stocomscuLogger, "Releasing Association");
			cond = ASC_releaseAssociation(assoc);
			if (cond.bad())
			{
				OFLOG_ERROR(stocomscuLogger, "Association Release Failed: " << DimseCondition::dump(temp_str, cond));
				return 1;
			}
		}
	}
	else if (cond == DUL_PEERREQUESTEDRELEASE)
	{
		OFLOG_ERROR(stocomscuLogger, "Protocol Error: Peer requested release (Aborting)");
		OFLOG_INFO(stocomscuLogger, "Aborting Association");
		cond = ASC_abortAssociation(assoc);
		if (cond.bad()) {
			OFLOG_ERROR(stocomscuLogger, "Association Abort Failed: " << DimseCondition::dump(temp_str, cond));
			return 1;
		}
	}
	else if (cond == DUL_PEERABORTEDASSOCIATION)
	{
		OFLOG_INFO(stocomscuLogger, "Peer Aborted Association");
	}
	else
	{
		OFLOG_ERROR(stocomscuLogger, "Store SCU Failed: " << DimseCondition::dump(temp_str, cond));
		OFLOG_INFO(stocomscuLogger, "Aborting Association");
		cond = ASC_abortAssociation(assoc);
		if (cond.bad()) {
			OFLOG_ERROR(stocomscuLogger, "Association Abort Failed: " << DimseCondition::dump(temp_str, cond));
			return 1;
		}
	}

	/* destroy the association, i.e. free memory of T_ASC_Association* structure. This */
	/* call is the counterpart of ASC_requestAssociation(...) which was called above. */
	cond = ASC_destroyAssociation(&assoc);
	if (cond.bad()) {
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		return 1;
	}
	/* drop the network, i.e. free memory of T_ASC_Network* structure. This call */
	/* is the counterpart of ASC_initializeNetwork(...) which was called above. */
	cond = ASC_dropNetwork(&net);
	if (cond.bad()) {
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		return 1;
	}

	OFStandard::shutdownNetwork();

	cond = tlsOptions.writeRandomSeed();
	if (cond.bad()) {
		// failure to write back the random seed is a warning, not an error
		OFLOG_WARN(stocomscuLogger, DimseCondition::dump(temp_str, cond));
	}

	return lastStatusCode;
}


static OFBool
isaListMember(OFList<OFString> &lst, OFString &s)
{
	OFListIterator(OFString) cur = lst.begin();
	OFListIterator(OFString) end = lst.end();

	OFBool found = OFFalse;
	while (cur != end && !found) {
		found = (s == *cur);
		++cur;
	}

	return found;
}

static OFCondition
addPresentationContext(T_ASC_Parameters *params,
	int presentationContextId,
	const OFString &abstractSyntax,
	const OFString &transferSyntax,
	T_ASC_SC_ROLE proposedRole = ASC_SC_ROLE_DEFAULT)
{
	const char *c_p = transferSyntax.c_str();
	OFCondition cond = ASC_addPresentationContext(params, presentationContextId,
		abstractSyntax.c_str(), &c_p, 1, proposedRole);
	return cond;
}

static OFCondition
addPresentationContext(T_ASC_Parameters *params,
	int presentationContextId,
	const OFString &abstractSyntax,
	const OFList<OFString> &transferSyntaxList,
	T_ASC_SC_ROLE proposedRole = ASC_SC_ROLE_DEFAULT)
{
	// create an array of supported/possible transfer syntaxes
	const char **transferSyntaxes = new const char*[transferSyntaxList.size()];
	int transferSyntaxCount = 0;
	OFListConstIterator(OFString) s_cur = transferSyntaxList.begin();
	OFListConstIterator(OFString) s_end = transferSyntaxList.end();
	while (s_cur != s_end) {
		transferSyntaxes[transferSyntaxCount++] = (*s_cur).c_str();
		++s_cur;
	}

	OFCondition cond = ASC_addPresentationContext(params, presentationContextId,
		abstractSyntax.c_str(), transferSyntaxes, transferSyntaxCount, proposedRole);

	delete[] transferSyntaxes;
	return cond;
}

static OFCondition
addStorageCommPresentationContexts(T_ASC_Parameters *params)
{
	/*
	 * Each SOP Class will be proposed in two presentation contexts (unless
	 * the opt_combineProposedTransferSyntaxes global variable is true).
	 * The command line specified a preferred transfer syntax to use.
	 * This prefered transfer syntax will be proposed in one
	 * presentation context and a set of alternative (fallback) transfer
	 * syntaxes will be proposed in a different presentation context.
	 *
	 * Generally, we prefer to use Explicitly encoded transfer syntaxes
	 * and if running on a Little Endian machine we prefer
	 * LittleEndianExplicitTransferSyntax to BigEndianTransferSyntax.
	 * Some SCP implementations will just select the first transfer
	 * syntax they support (this is not part of the standard) so
	 * organise the proposed transfer syntaxes to take advantage
	 * of such behaviour.
	 */

	 // Which transfer syntax was preferred on the command line
	OFString preferredTransferSyntax;
	if (opt_networkTransferSyntax == EXS_Unknown) {
		/* gLocalByteOrder is defined in dcxfer.h */
		if (gLocalByteOrder == EBO_LittleEndian) {
			/* we are on a little endian machine */
			preferredTransferSyntax = UID_LittleEndianExplicitTransferSyntax;
		}
		else {
			/* we are on a big endian machine */
			preferredTransferSyntax = UID_BigEndianExplicitTransferSyntax;
		}
	}
	else {
		DcmXfer xfer(opt_networkTransferSyntax);
		preferredTransferSyntax = xfer.getXferID();
	}

	OFListIterator(OFString) s_cur;
	OFListIterator(OFString) s_end;

	OFList<OFString> fallbackSyntaxes;
	// - If little endian implicit is preferred, we don't need any fallback syntaxes
	//   because it is the default transfer syntax and all applications must support it.
	if ((opt_networkTransferSyntax != EXS_LittleEndianImplicit))
	{
		fallbackSyntaxes.push_back(UID_LittleEndianExplicitTransferSyntax);
		fallbackSyntaxes.push_back(UID_BigEndianExplicitTransferSyntax);
		fallbackSyntaxes.push_back(UID_LittleEndianImplicitTransferSyntax);
		// Remove the preferred syntax from the fallback list
		fallbackSyntaxes.remove(preferredTransferSyntax);
	}

	// create a list of transfer syntaxes combined from the preferred and fallback syntaxes
	OFList<OFString> combinedSyntaxes;
	s_cur = fallbackSyntaxes.begin();
	s_end = fallbackSyntaxes.end();
	combinedSyntaxes.push_back(preferredTransferSyntax);
	while (s_cur != s_end)
	{
		if (!isaListMember(combinedSyntaxes, *s_cur)) combinedSyntaxes.push_back(*s_cur);
		++s_cur;
	}

	OFList<OFString> sopClasses;
	sopClasses.push_back(UID_StorageCommitmentPushModelSOPClass); //"1.2.840.10008.1.20.1" Storage Commitment Push Model SOP Class UID

	// thin out the SOP classes to remove any duplicates
	OFList<OFString> sops;
	s_cur = sopClasses.begin();
	s_end = sopClasses.end();
	while (s_cur != s_end) {
		if (!isaListMember(sops, *s_cur)) {
			sops.push_back(*s_cur);
		}
		++s_cur;
	}

	// add a presentations context for each SOP class / transfer syntax pair
	OFCondition cond = EC_Normal;
	int pid = 1; // presentation context id
	s_cur = sops.begin();
	s_end = sops.end();
	while (s_cur != s_end && cond.good()) {

		if (pid > 255) {
			OFLOG_ERROR(stocomscuLogger, "Too many presentation contexts");
			return ASC_BADPRESENTATIONCONTEXTID;
		}

			// SOP class with preferred transfer syntax
			cond = addPresentationContext(params, pid, *s_cur, preferredTransferSyntax);
			pid += 2;   /* only odd presentation context id's */

			if (fallbackSyntaxes.size() > 0) {
				if (pid > 255) {
					OFLOG_ERROR(stocomscuLogger, "Too many presentation contexts");
					return ASC_BADPRESENTATIONCONTEXTID;
				}

				// SOP class with fallback transfer syntax
				cond = addPresentationContext(params, pid, *s_cur, fallbackSyntaxes);
				pid += 2; /* only odd presentation context id's */
			}

		++s_cur;
	}

	return cond;
}


static OFCondition
storecommSCU(T_ASC_Association *assoc, const OFList<OFString>& sopClassUIDList,
	const OFList<OFString>& sopInstanceUIDList)
	/*
	* This function will appens all sop informations and send them to SCP.
	*
	* Parameters:
	*   assoc - [in] The association (network connection to another DICOM application).
	*   sopClassUIDList - [in] SOP class UID of each insance.
	*   sopInstanceUIDList - [in] SOP isntance UID of each insance.
	*/
{
	DIC_US msgId = assoc->nextMsgID++;
	T_ASC_PresentationContextID presID;

	OFString tempStr;
	OFCondition cond;
	T_DIMSE_Message request;
	// Make sure everything is zeroed (especially options)
	bzero((char*)&request, sizeof(request));
	T_DIMSE_N_ActionRQ &actionReq = request.msg.NActionRQ;
	DcmDataset *statusDetail = NULL;
	request.CommandField = DIMSE_N_ACTION_RQ;

	OFLOG_INFO(stocomscuLogger, "Sending N-Action request: ");

	presID = ASC_findAcceptedPresentationContextID(assoc, UID_StorageCommitmentPushModelSOPClass);
	if (presID == 0) {
		OFLOG_ERROR(stocomscuLogger, "No valid presentation context " << UID_StorageCommitmentPushModelSOPClass);
		return DIMSE_NOVALIDPRESENTATIONCONTEXTID;
	}

	T_ASC_PresentationContext pc;
	ASC_findAcceptedPresentationContext(assoc->params, presID, &pc);

	/* prepare the transmission of data */
	bzero(OFreinterpret_cast(char *, &actionReq), sizeof(actionReq));
	actionReq.MessageID = msgId;
	actionReq.DataSetType = DIMSE_DATASET_PRESENT;
	actionReq.ActionTypeID = 1; // action type for storage commitment refer to part04 Table J.3-1. Storage Commitment Request

	OFStandard::strlcpy(actionReq.RequestedSOPClassUID, UID_StorageCommitmentPushModelSOPClass, sizeof(actionReq.RequestedSOPClassUID));
	OFStandard::strlcpy(actionReq.RequestedSOPInstanceUID, UID_StorageCommitmentPushModelSOPInstance, sizeof(actionReq.RequestedSOPInstanceUID));

	// DcmDataset datasq;
	DcmDataset reqdataset;

	//TransactionUID
	DIC_UI transUid;
	dcmGenerateUniqueIdentifier(transUid, NULL);
	reqdataset.putAndInsertString(DCM_TransactionUID, transUid);

	OFListIterator(OFString) sopclass_iter = sopClassUIDList.begin();
	OFListIterator(OFString) sopclass_last = sopClassUIDList.end();
	OFListIterator(OFString) sopinstance_iter = sopInstanceUIDList.begin();
	OFListIterator(OFString) sopinstance_last = sopInstanceUIDList.end();

	OFLOG_INFO(stocomscuLogger, "append n-action dataset ...");
	while (sopinstance_iter != sopinstance_last && sopclass_iter != sopclass_last)
	{
		DcmItem *item = NULL;
		cond = reqdataset.findOrCreateSequenceItem(DCM_ReferencedSOPSequence, item, -2 /* append */);
		if (cond.good())
		{
			item->putAndInsertString(DCM_ReferencedSOPClassUID, sopclass_iter->c_str());
			item->putAndInsertString(DCM_ReferencedSOPInstanceUID, sopinstance_iter->c_str());

			sopclass_iter++;
			sopinstance_iter++;
		}
		else
		{
			OFLOG_ERROR(stocomscuLogger, "Failed add sequence items to N-ACTION dataset.");
			return DIMSE_BADDATA;
		}
	}

	// Send request
	if (stocomscuLogger.isEnabledFor(OFLogger::DEBUG_LOG_LEVEL))
	{
		OFLOG_INFO(stocomscuLogger, "Sending N-ACTION Request");
		OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, request, DIMSE_OUTGOING, &reqdataset, presID));
	}
	else {
		OFLOG_INFO(stocomscuLogger, "Sending N-ACTION Request (MsgID " << actionReq.MessageID << ")");
	}

	/* call the corresponding DIMSE function to send the message */
	cond = DIMSE_sendMessageUsingMemoryData(assoc, presID, &request, NULL /*statusDetail*/, &reqdataset,
		NULL /*callback*/, NULL /*callbackData*/, NULL/*commandSet*/);
	if (cond.bad())
	{
		OFLOG_ERROR(stocomscuLogger, "Failed sending N-ACTION request: " << DimseCondition::dump(tempStr, cond));
		return cond;
	}

	// Receive response
	T_DIMSE_Message response;
	bzero((char*)&response, sizeof(response));
	cond = DIMSE_receiveCommand(assoc, opt_blockMode, opt_dimse_timeout, &presID,
		&response, &statusDetail, NULL /*commandSet*/);
	if (cond.bad())
	{
		DCMNET_ERROR("Failed receiving DIMSE response: " << DimseCondition::dump(tempStr, cond));
		return cond;
	}

	// Check command set
	if (response.CommandField == DIMSE_N_ACTION_RSP)
	{
		if (DCM_dcmnetLogger.isEnabledFor(OFLogger::DEBUG_LOG_LEVEL))
		{
			OFLOG_INFO(stocomscuLogger, "Received N-ACTION Response");
			OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, response, DIMSE_INCOMING, NULL, presID));
		}
		else {
			OFLOG_INFO(stocomscuLogger, "Received N-ACTION Response (" << DU_nactionStatusString(response.msg.NActionRSP.DimseStatus) << ")");
		}
	}
	else {
		OFLOG_ERROR(stocomscuLogger, "Expected N-ACTION response but received DIMSE command 0x"
			<< STD_NAMESPACE hex << STD_NAMESPACE setfill('0') << STD_NAMESPACE setw(4)
			<< OFstatic_cast(unsigned int, response.CommandField));
		OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, response, DIMSE_INCOMING, NULL, presID));
		delete statusDetail;
		return DIMSE_BADCOMMANDTYPE;
	}
	if (statusDetail != NULL)
	{
		DCMNET_DEBUG("Response has status detail:" << OFendl << DcmObject::PrintHelper(*statusDetail));
		delete statusDetail;
	}

	// Set return value
	T_DIMSE_N_ActionRSP &actionRsp = response.msg.NActionRSP;
	Uint16 rspStatusCode = actionRsp.DimseStatus;

	// Check whether there is a dataset to be received
	if (actionRsp.DataSetType == DIMSE_DATASET_PRESENT)
	{
		// this should never happen
		DcmDataset *tempDataset = NULL;
		T_ASC_PresentationContextID tempID;
		DCMNET_WARN("Trying to retrieve unexpected dataset in N-ACTION response");
		//cond = receiveDIMSEDataset(&tempID, &tempDataset);
		cond = DIMSE_receiveDataSetInMemory(assoc, opt_blockMode, opt_dimse_timeout, &tempID, &tempDataset, //presID, dataObject,
			NULL /*callback*/, NULL /*callbackData*/);
		if (cond.good())
		{
			DCMNET_WARN("Received unexpected dataset after N-ACTION response, ignoring");
			delete tempDataset;
		}
		else {
			return DIMSE_BADDATA;
		}
	}
	if (actionRsp.MessageIDBeingRespondedTo != actionReq.MessageID)
	{
		// since we only support synchronous communication, the message ID in the response
		// should be identical to the one in the request
		DCMNET_ERROR("Received response with wrong message ID (" << actionRsp.MessageIDBeingRespondedTo
			<< " instead of " << actionReq.MessageID << ")");
		return DIMSE_BADMESSAGE;
	}

	/* return */
	return cond;
}



static OFBool
findSOPClassAndInstanceInFile(
	const char *fname,
	char *sopClass,
	size_t sopClassSize,
	char *sopInstance,
	size_t sopInstanceSize)
{
	DcmFileFormat ff;
	if (!ff.loadFile(fname, EXS_Unknown, EGL_noChange, DCM_MaxReadLength, opt_readMode).good())
		return OFFalse;

	/* look in the meta-header first */
	OFBool found = DU_findSOPClassAndInstanceInDataSet(ff.getMetaInfo(), sopClass, sopClassSize, sopInstance, sopInstanceSize, opt_correctUIDPadding);

	if (!found)
		found = DU_findSOPClassAndInstanceInDataSet(ff.getDataset(), sopClass, sopClassSize, sopInstance, sopInstanceSize, opt_correctUIDPadding);

	return found;
}

static OFCondition acceptAssociation(T_ASC_Network *net, DcmAssociationConfiguration& asccfg, OFBool secureConnection)
{
	char buf[BUFSIZ];
	T_ASC_Association *assoc;
	OFCondition cond;
	OFString sprofile;
	OFString temp_str;

	const char* knownAbstractSyntaxes[] =
	{
		UID_VerificationSOPClass
	};

	const char* storageCommitmentAbstractSyntaxes[] =
	{
		UID_StorageCommitmentPushModelSOPClass
	};

	const char* transferSyntaxes[] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  // 10
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  // 20
		NULL };                                                      // +1
	int numTransferSyntaxes = 0;

	// try to receive an association using blocking mode

	cond = ASC_receiveAssociation(net, &assoc, opt_maxReceivePDULength, NULL, NULL, secureConnection);


	// if some kind of error occurred, take care of it
	if (cond.bad())
	{
		// check what kind of error occurred. If no association was
		// received, check if certain other conditions are met
		if (cond == DUL_NOASSOCIATIONREQUEST)
		{
		}
		// If something else was wrong we might have to dump an error message.
		else
		{
			OFLOG_ERROR(stocomscuLogger, "Receiving Association failed: " << DimseCondition::dump(temp_str, cond));
		}

		// no matter what kind of error occurred, we need to do a cleanup
		goto cleanup;
	}
	OFLOG_INFO(stocomscuLogger, "Association Received");

	/* dump presentation contexts if required */
	if (opt_showPresentationContexts)
		OFLOG_INFO(stocomscuLogger, "Parameters:" << OFendl << ASC_dumpParameters(temp_str, assoc->params, ASC_ASSOC_RQ));
	else
		OFLOG_DEBUG(stocomscuLogger, "Parameters:" << OFendl << ASC_dumpParameters(temp_str, assoc->params, ASC_ASSOC_RQ));

	if (opt_refuseAssociation)
	{
		T_ASC_RejectParameters rej =
		{
			ASC_RESULT_REJECTEDPERMANENT,
			ASC_SOURCE_SERVICEUSER,
			ASC_REASON_SU_NOREASON
		};

		OFLOG_INFO(stocomscuLogger, "Refusing Association (forced via command line)");
		cond = ASC_rejectAssociation(assoc, &rej);
		if (cond.bad())
		{
			OFLOG_ERROR(stocomscuLogger, "Association Reject Failed: " << DimseCondition::dump(temp_str, cond));
		}
		goto cleanup;
	}

	switch (opt_networkTransferSyntax)
	{
	case EXS_LittleEndianImplicit:
		/* we only support Little Endian Implicit */
		transferSyntaxes[0] = UID_LittleEndianImplicitTransferSyntax;
		numTransferSyntaxes = 1;
		break;
	case EXS_LittleEndianExplicit:
		/* we prefer Little Endian Explicit */
		transferSyntaxes[0] = UID_LittleEndianExplicitTransferSyntax;
		transferSyntaxes[1] = UID_BigEndianExplicitTransferSyntax;
		transferSyntaxes[2] = UID_LittleEndianImplicitTransferSyntax;
		numTransferSyntaxes = 3;
		break;
	case EXS_BigEndianExplicit:
		/* we prefer Big Endian Explicit */
		transferSyntaxes[0] = UID_BigEndianExplicitTransferSyntax;
		transferSyntaxes[1] = UID_LittleEndianExplicitTransferSyntax;
		transferSyntaxes[2] = UID_LittleEndianImplicitTransferSyntax;
		numTransferSyntaxes = 3;
		break;

	default:
		 {
			/* We prefer explicit transfer syntaxes.
			* If we are running on a Little Endian machine we prefer
			* LittleEndianExplicitTransferSyntax to BigEndianTransferSyntax.
			*/
			if (gLocalByteOrder == EBO_LittleEndian)  /* defined in dcxfer.h */
			{
				transferSyntaxes[0] = UID_LittleEndianExplicitTransferSyntax;
				transferSyntaxes[1] = UID_BigEndianExplicitTransferSyntax;
			}
			else
			{
				transferSyntaxes[0] = UID_BigEndianExplicitTransferSyntax;
				transferSyntaxes[1] = UID_LittleEndianExplicitTransferSyntax;
			}
			transferSyntaxes[2] = UID_LittleEndianImplicitTransferSyntax;
			numTransferSyntaxes = 3;
		}
		break;
	}

	{
		/* accept the Verification SOP Class if presented */
		cond = ASC_acceptContextsWithPreferredTransferSyntaxes(assoc->params, knownAbstractSyntaxes, DIM_OF(knownAbstractSyntaxes), transferSyntaxes, numTransferSyntaxes);
		if (cond.bad())
		{
			OFLOG_DEBUG(stocomscuLogger, DimseCondition::dump(temp_str, cond));
			goto cleanup;
		}

		/* accept the Storage commitment SOP Class if presented */
		cond = ASC_acceptContextsWithPreferredTransferSyntaxes(assoc->params, storageCommitmentAbstractSyntaxes, DIM_OF(storageCommitmentAbstractSyntaxes), transferSyntaxes, numTransferSyntaxes);
		if (cond.bad())
		{
			OFLOG_DEBUG(stocomscuLogger, DimseCondition::dump(temp_str, cond));
			goto cleanup;
		}

		if (opt_promiscuous)
		{
			/* accept everything not known not to be a storage SOP class */
			cond = acceptUnknownContextsWithPreferredTransferSyntaxes(
				assoc->params, transferSyntaxes, numTransferSyntaxes);
			if (cond.bad())
			{
				OFLOG_DEBUG(stocomscuLogger, DimseCondition::dump(temp_str, cond));
				goto cleanup;
			}
		}
	}

	/* set our app title */
	ASC_setAPTitles(assoc->params, NULL, NULL, opt_respondingAETitle);

	/* acknowledge or reject this association */
	cond = ASC_getApplicationContextName(assoc->params, buf, sizeof(buf));
	if ((cond.bad()) || strcmp(buf, UID_StandardApplicationContext) != 0)
	{
		/* reject: the application context name is not supported */
		T_ASC_RejectParameters rej =
		{
			ASC_RESULT_REJECTEDPERMANENT,
			ASC_SOURCE_SERVICEUSER,
			ASC_REASON_SU_APPCONTEXTNAMENOTSUPPORTED
		};

		OFLOG_INFO(stocomscuLogger, "Association Rejected: Bad Application Context Name: " << buf);
		cond = ASC_rejectAssociation(assoc, &rej);
		if (cond.bad())
		{
			OFLOG_DEBUG(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		}
		goto cleanup;

	}
	else if (opt_rejectWithoutImplementationUID && strlen(assoc->params->theirImplementationClassUID) == 0)
	{
		/* reject: the no implementation Class UID provided */
		T_ASC_RejectParameters rej =
		{
			ASC_RESULT_REJECTEDPERMANENT,
			ASC_SOURCE_SERVICEUSER,
			ASC_REASON_SU_NOREASON
		};

		OFLOG_INFO(stocomscuLogger, "Association Rejected: No Implementation Class UID provided");
		cond = ASC_rejectAssociation(assoc, &rej);
		if (cond.bad())
		{
			OFLOG_DEBUG(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		}
		goto cleanup;
	}
	else
	{

		cond = ASC_acknowledgeAssociation(assoc);
		if (cond.bad())
		{
			OFLOG_ERROR(stocomscuLogger, DimseCondition::dump(temp_str, cond));
			goto cleanup;
		}
		OFLOG_INFO(stocomscuLogger, "Association Acknowledged (Max Send PDV: " << assoc->sendPDVLength << ")");
		if (ASC_countAcceptedPresentationContexts(assoc->params) == 0)
			OFLOG_INFO(stocomscuLogger, "    (but no valid presentation contexts)");
		/* dump the presentation contexts which have been accepted/refused */
		if (opt_showPresentationContexts)
			OFLOG_INFO(stocomscuLogger, ASC_dumpParameters(temp_str, assoc->params, ASC_ASSOC_AC));
		else
			OFLOG_DEBUG(stocomscuLogger, ASC_dumpParameters(temp_str, assoc->params, ASC_ASSOC_AC));
	}

#ifdef BUGGY_IMPLEMENTATION_CLASS_UID_PREFIX
	/* active the dcmPeerRequiresExactUIDCopy workaround code
	* (see comments in dimse.h) for a implementation class UID
	* prefix known to exhibit the buggy behaviour.
	*/
	if (0 == strncmp(assoc->params->theirImplementationClassUID,
		BUGGY_IMPLEMENTATION_CLASS_UID_PREFIX,
		strlen(BUGGY_IMPLEMENTATION_CLASS_UID_PREFIX)))
	{
		dcmEnableAutomaticInputDataCorrection.set(OFFalse);
		dcmPeerRequiresExactUIDCopy.set(OFTrue);
	}
#endif

	// store previous values for later use
	lastCallingAETitle = callingAETitle;
	lastCalledAETitle = calledAETitle;
	lastCallingPresentationAddress = callingPresentationAddress;
	// store calling and called aetitle in global variables to enable
	// the --exec options using them. Enclose in quotation marks because
	// aetitles may contain space characters.
	DIC_AE callingTitle;
	DIC_AE calledTitle;
	if (ASC_getAPTitles(assoc->params, callingTitle, sizeof(callingTitle), calledTitle, sizeof(calledTitle), NULL, 0).good())
	{
		callingAETitle = "\"";
		callingAETitle += OFSTRING_GUARD(callingTitle);
		callingAETitle += "\"";
		calledAETitle = "\"";
		calledAETitle += OFSTRING_GUARD(calledTitle);
		calledAETitle += "\"";
	}
	else
	{
		// should never happen
		callingAETitle.clear();
		calledAETitle.clear();
	}
	// store calling presentation address (i.e. remote hostname)
	callingPresentationAddress = OFSTRING_GUARD(assoc->params->DULparams.callingPresentationAddress);

	/* now do the real work, i.e. receive DIMSE commands over the network connection */
	/* which was established and handle these commands correspondingly.*/
	cond = processCommands(assoc);

	if (cond == DUL_PEERREQUESTEDRELEASE)
	{
		OFLOG_INFO(stocomscuLogger, "Association Release");
		cond = ASC_acknowledgeRelease(assoc);
	}
	else if (cond == DUL_PEERABORTEDASSOCIATION)
	{
		OFLOG_INFO(stocomscuLogger, "Association Aborted");
	}
	else
	{
		OFLOG_ERROR(stocomscuLogger, "DIMSE failure (aborting association): " << DimseCondition::dump(temp_str, cond));
		/* some kind of error so abort the association */
		cond = ASC_abortAssociation(assoc);
	}

cleanup:

	if (cond.code() == DULC_FORKEDCHILD) return cond;

	cond = ASC_dropSCPAssociation(assoc);
	if (cond.bad())
	{
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		exit(1);
	}
	cond = ASC_destroyAssociation(&assoc);
	if (cond.bad())
	{
		OFLOG_FATAL(stocomscuLogger, DimseCondition::dump(temp_str, cond));
		exit(1);
	}

	return cond;
}


static OFCondition
processCommands(T_ASC_Association * assoc)
/*
* This function receives DIMSE commands over the network connection
* and handles these commands correspondingly. Note that in case of
* storescp only C-ECHO-RQ and C-STORE-RQ commands can be processed.
*
* Parameters:
*   assoc - [in] The association (network connection to another DICOM application).
*/
{
	OFCondition cond = EC_Normal;
	T_DIMSE_Message msg;
	T_ASC_PresentationContextID presID = 0;
	DcmDataset *statusDetail = NULL;

	// start a loop to be able to receive more than one DIMSE command
	while (cond == EC_Normal || cond == DIMSE_NODATAAVAILABLE || cond == DIMSE_OUTOFRESOURCES)
	{
		// receive a DIMSE command over the network
		cond = DIMSE_receiveCommand(assoc, DIMSE_BLOCKING, 0, &presID, &msg, &statusDetail);


		// if the command which was received has extra status
		// detail information, dump this information
		if (statusDetail != NULL)
		{
			OFLOG_DEBUG(stocomscuLogger, "Status Detail:" << OFendl << DcmObject::PrintHelper(*statusDetail));
			delete statusDetail;
		}

		// check if peer did release or abort, or if we have a valid message
		if (cond == EC_Normal)
		{
			// in case we received a valid message, process this command
			// note that storescp can only process a C-ECHO-RQ and a C-STORE-RQ
			switch (msg.CommandField)
			{
			case DIMSE_C_ECHO_RQ:
				// process C-ECHO-Request
				cond = echoSCP(assoc, &msg, presID);
				break;
				
			case DIMSE_N_EVENT_REPORT_RQ:
				// process N-EVENT-REPORT RQ 
				cond = eventReportSCP(assoc, &msg, presID);
				break;
			default:
				OFString tempStr;
				// we cannot handle this kind of message
				cond = DIMSE_BADCOMMANDTYPE;
				OFLOG_ERROR(stocomscuLogger, "Expected C-ECHO or C-STORE request but received DIMSE command 0x"
					<< STD_NAMESPACE hex << STD_NAMESPACE setfill('0') << STD_NAMESPACE setw(4)
					<< OFstatic_cast(unsigned, msg.CommandField));
				OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, msg, DIMSE_INCOMING, NULL, presID));
				break;
			}
		}
	}
	return cond;
}


static OFCondition echoSCP(T_ASC_Association * assoc, T_DIMSE_Message * msg, T_ASC_PresentationContextID presID)
{
	OFString temp_str;
	// assign the actual information of the C-Echo-RQ command to a local variable
	T_DIMSE_C_EchoRQ *req = &msg->msg.CEchoRQ;
	if (stocomscuLogger.isEnabledFor(OFLogger::DEBUG_LOG_LEVEL))
	{
		OFLOG_INFO(stocomscuLogger, "Received Echo Request");
		OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(temp_str, *req, DIMSE_INCOMING, NULL, presID));
	}
	else {
		OFLOG_INFO(stocomscuLogger, "Received Echo Request (MsgID " << req->MessageID << ")");
	}

	/* the echo succeeded !! */
	OFCondition cond = DIMSE_sendEchoResponse(assoc, presID, req, STATUS_Success, NULL);
	if (cond.bad())
	{
		OFLOG_ERROR(stocomscuLogger, "Echo SCP Failed: " << DimseCondition::dump(temp_str, cond));
	}
	return cond;
}

static OFCondition eventReportSCP(
	T_ASC_Association *assoc,
	T_DIMSE_Message *msg,
	T_ASC_PresentationContextID presID)
	/*
	* This function processes a DIMSE C-STORE-RQ command that was
	* received over the network connection.
	*
	* Parameters:
	*   assoc  - [in] The association (network connection to another DICOM application).
	*   msg    - [in] The DIMSE C-STORE-RQ message that was received.
	*   presID - [in] The ID of the presentation context which was specified in the PDV which contained
	*                 the DIMSE command.
	*/
{
	OFCondition cond = EC_Normal;
	T_DIMSE_N_EventReportRQ *req;
	OFString tempStr;
	//	T_ASC_PresentationContextID presIDdset;
		//	char imageFileName[2048];
	DcmDataset *dataset = NULL;
	// DcmDataset *statusDetail = NULL; // TODO: do we need this and if so, how do we get it?
	Uint16 rspStatusCode = 0;
	//	// assign the actual information of the C-STORE-RQ command to a local variable
	req = &msg->msg.NEventReportRQ;

	T_DIMSE_N_EventReportRQ *reqMessage = req;

	// Check if dataset is announced correctly
	if (reqMessage->DataSetType == DIMSE_DATASET_NULL)
	{
		OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, *reqMessage, DIMSE_INCOMING, NULL, presID));
		OFLOG_ERROR(stocomscuLogger, "Received N-EVENT-REPORT request but no dataset announced, aborting");
		return DIMSE_BADMESSAGE;
	}

	// Receive dataset
	cond = DIMSE_receiveDataSetInMemory(assoc, opt_blockMode, opt_dimse_timeout,
		&presID, &dataset, NULL /*callback*/, NULL /*callbackData*/);

	if (cond.good())
	{
		OFLOG_DEBUG(stocomscuLogger, "Received dataset on presentation context " << OFstatic_cast(unsigned int, presID));
	}
	else {
		OFString tempStr;
		OFLOG_ERROR(stocomscuLogger, "Unable to receive dataset on presentation context "
			<< OFstatic_cast(unsigned int, presID) << ": " << DimseCondition::dump(tempStr, cond));
	}

	if (cond.bad())
	{
		OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, *reqMessage, DIMSE_INCOMING, NULL, presID));
		OFLOG_ERROR(stocomscuLogger, "Unable to receive N-EVENT-REPORT dataset on presentation context " << OFstatic_cast(unsigned int, presID));
		return DIMSE_BADDATA;
	}

	// Output dataset only if trace level is enabled
	if (DCM_dcmnetLogger.isEnabledFor(OFLogger::DEBUG_LOG_LEVEL))
		OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, *reqMessage, DIMSE_INCOMING, dataset, presID));
	else
		OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, *reqMessage, DIMSE_INCOMING, NULL, presID));

	// 暂时不处理
	// Compare presentation context ID of command and data set
	//if (presIDdset != presID)
	//{
	//	DCMNET_ERROR("Presentation Context ID of command (" << OFstatic_cast(unsigned int, presID)
	//		<< ") and data set (" << OFstatic_cast(unsigned int, presIDdset) << ") differs");
	//	delete dataset;
	//	return makeDcmnetCondition(DIMSEC_INVALIDPRESENTATIONCONTEXTID, OF_error,
	//		"DIMSE: Presentation Contexts of Command and Data Set differ");
	//}

	// Check the request message and dataset and return the DIMSE status code to be used
	rspStatusCode = STATUS_Success; // checkEVENTREPORTRequest(reqMessage, dataset);

	// Send back response
	T_DIMSE_Message response;
	// Make sure everything is zeroed (especially options)
	bzero((char*)&response, sizeof(response));
	T_DIMSE_N_EventReportRSP &eventReportRsp = response.msg.NEventReportRSP;
	response.CommandField = DIMSE_N_EVENT_REPORT_RSP;
	eventReportRsp.MessageIDBeingRespondedTo = reqMessage->MessageID;
	eventReportRsp.DimseStatus = rspStatusCode;
	eventReportRsp.DataSetType = DIMSE_DATASET_NULL;
	// Do not send any optional fields
	eventReportRsp.opts = 0;
	eventReportRsp.AffectedSOPClassUID[0] = 0;
	eventReportRsp.AffectedSOPInstanceUID[0] = 0;

	if (DCM_dcmnetLogger.isEnabledFor(OFLogger::DEBUG_LOG_LEVEL))
	{
		OFLOG_INFO(stocomscuLogger, "Sending N-EVENT-REPORT Response");
		OFLOG_DEBUG(stocomscuLogger, DIMSE_dumpMessage(tempStr, response, DIMSE_OUTGOING, NULL, presID));
	}
	else {
		OFLOG_INFO(stocomscuLogger, "Sending N-EVENT-REPORT Response (" << DU_neventReportStatusString(rspStatusCode) << ")");
	}
	// Send response message
	cond = DIMSE_sendMessageUsingMemoryData(assoc, presID, &response, NULL /*statusDetail*/, NULL /* dataObject */,
		NULL /*callback*/, NULL /*callbackData*/, NULL/*commandSet*/);
	if (cond.bad())
	{
		OFLOG_ERROR(stocomscuLogger, "Failed sending N-EVENT-REPORT response: " << DimseCondition::dump(tempStr, cond));
		delete dataset;
		return cond;
	}

	//// if opt_sleepAfter is set, the user requires that the application shall
	//// sleep a certain amount of seconds after storing the instance data.
	//if (opt_sleepAfter > 0)
	//{
	//	OFStandard::sleep(OFstatic_cast(unsigned int, opt_sleepAfter));
	//}

	// return return value
	return cond;
}

static
DUL_PRESENTATIONCONTEXT *
findPresentationContextID(LST_HEAD * head,
	T_ASC_PresentationContextID presentationContextID)
{
	DUL_PRESENTATIONCONTEXT *pc;
	LST_HEAD **l;
	OFBool found = OFFalse;

	if (head == NULL)
		return NULL;

	l = &head;
	if (*l == NULL)
		return NULL;

	pc = OFstatic_cast(DUL_PRESENTATIONCONTEXT *, LST_Head(l));
	(void)LST_Position(l, OFstatic_cast(LST_NODE *, pc));

	while (pc && !found) {
		if (pc->presentationContextID == presentationContextID) {
			found = OFTrue;
		}
		else {
			pc = OFstatic_cast(DUL_PRESENTATIONCONTEXT *, LST_Next(l));
		}
	}
	return pc;
}


/** accept all presentation contexts for unknown SOP classes,
*  i.e. UIDs appearing in the list of abstract syntaxes
*  where no corresponding name is defined in the UID dictionary.
*  @param params pointer to association parameters structure
*  @param transferSyntax transfer syntax to accept
*  @param acceptedRole SCU/SCP role to accept
*/
static OFCondition acceptUnknownContextsWithTransferSyntax(
	T_ASC_Parameters * params,
	const char* transferSyntax,
	T_ASC_SC_ROLE acceptedRole)
{
	OFCondition cond = EC_Normal;
	int n, i, k;
	DUL_PRESENTATIONCONTEXT *dpc;
	T_ASC_PresentationContext pc;
	OFBool accepted = OFFalse;
	OFBool abstractOK = OFFalse;

	n = ASC_countPresentationContexts(params);
	for (i = 0; i < n; i++)
	{
		cond = ASC_getPresentationContext(params, i, &pc);
		if (cond.bad()) return cond;
		abstractOK = OFFalse;
		accepted = OFFalse;

		if (dcmFindNameOfUID(pc.abstractSyntax) == NULL)
		{
			abstractOK = OFTrue;

			/* check the transfer syntax */
			for (k = 0; (k < OFstatic_cast(int, pc.transferSyntaxCount)) && !accepted; k++)
			{
				if (strcmp(pc.proposedTransferSyntaxes[k], transferSyntax) == 0)
				{
					accepted = OFTrue;
				}
			}
		}

		if (accepted)
		{
			cond = ASC_acceptPresentationContext(
				params, pc.presentationContextID,
				transferSyntax, acceptedRole);
			if (cond.bad()) return cond;
		}
		else {
			T_ASC_P_ResultReason reason;

			/* do not refuse if already accepted */
			dpc = findPresentationContextID(params->DULparams.acceptedPresentationContext,
				pc.presentationContextID);
			if ((dpc == NULL) || ((dpc != NULL) && (dpc->result != ASC_P_ACCEPTANCE)))
			{

				if (abstractOK) {
					reason = ASC_P_TRANSFERSYNTAXESNOTSUPPORTED;
				}
				else {
					reason = ASC_P_ABSTRACTSYNTAXNOTSUPPORTED;
				}
				/*
				* If previously this presentation context was refused
				* because of bad transfer syntax let it stay that way.
				*/
				if ((dpc != NULL) && (dpc->result == ASC_P_TRANSFERSYNTAXESNOTSUPPORTED))
					reason = ASC_P_TRANSFERSYNTAXESNOTSUPPORTED;

				cond = ASC_refusePresentationContext(params, pc.presentationContextID, reason);
				if (cond.bad()) return cond;
			}
		}
	}
	return EC_Normal;
}


/** accept all presentation contexts for unknown SOP classes,
*  i.e. UIDs appearing in the list of abstract syntaxes
*  where no corresponding name is defined in the UID dictionary.
*  This method is passed a list of "preferred" transfer syntaxes.
*  @param params pointer to association parameters structure
*  @param transferSyntax transfer syntax to accept
*  @param acceptedRole SCU/SCP role to accept
*/
static OFCondition acceptUnknownContextsWithPreferredTransferSyntaxes(
	T_ASC_Parameters * params,
	const char* transferSyntaxes[], int transferSyntaxCount,
	T_ASC_SC_ROLE acceptedRole)
{
	OFCondition cond = EC_Normal;
	/*
	** Accept in the order "least wanted" to "most wanted" transfer
	** syntax.  Accepting a transfer syntax will override previously
	** accepted transfer syntaxes.
	*/
	for (int i = transferSyntaxCount - 1; i >= 0; i--)
	{
		cond = acceptUnknownContextsWithTransferSyntax(params, transferSyntaxes[i], acceptedRole);
		if (cond.bad()) return cond;
	}
	return cond;
}
