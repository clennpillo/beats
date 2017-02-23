package drda

const Drda_MAGIC  = 0xD0

const Drda_CP_DATA          = 0x0000
const Drda_CP_CODPNT        = 0x000C
const Drda_CP_FDODSC        = 0x0010
const Drda_CP_TYPDEFNAM     = 0x002F
const Drda_CP_TYPDEFOVR     = 0x0035
const Drda_CP_CODPNTDR      = 0x0064
const Drda_CP_EXCSAT        = 0x1041
const Drda_CP_SYNCCTL       = 0x1055
const Drda_CP_SYNCRSY       = 0x1069
const Drda_CP_ACCSEC        = 0x106D
const Drda_CP_SECCHK        = 0x106E
const Drda_CP_SYNCLOG       = 0x106F
const Drda_CP_RSCTYP        = 0x111F
const Drda_CP_RSNCOD        = 0x1127
const Drda_CP_RSCNAM        = 0x112D
const Drda_CP_PRDID         = 0x112E
const Drda_CP_PRCCNVCD      = 0x113F
const Drda_CP_VRSNAM        = 0x1144
const Drda_CP_SRVCLSNM      = 0x1147
const Drda_CP_SVRCOD        = 0x1149
const Drda_CP_SYNERRCD      = 0x114A
const Drda_CP_SRVDGN        = 0x1153
const Drda_CP_SRVRLSLV      = 0x115A
const Drda_CP_SPVNAM        = 0x115D
const Drda_CP_EXTNAM        = 0x115E
const Drda_CP_SRVNAM        = 0x116D
const Drda_CP_SECMGRNM      = 0x1196
const Drda_CP_DEPERRCD      = 0x119B
const Drda_CP_CCSIDSBC      = 0x119C
const Drda_CP_CCSIDDBC      = 0x119D
const Drda_CP_CCSIDMBC      = 0x119E
const Drda_CP_USRID         = 0x11A0
const Drda_CP_PASSWORD      = 0x11A1
const Drda_CP_SECMEC        = 0x11A2
const Drda_CP_SECCHKCD      = 0x11A4
const Drda_CP_SVCERRNO      = 0x11B4
const Drda_CP_SECTKN        = 0x11DC
const Drda_CP_NEWPASSWORD   = 0x11DE
const Drda_CP_MGRLVLRM      = 0x1210
const Drda_CP_MGRDEPRM      = 0x1218
const Drda_CP_SECCHKRM      = 0x1219
const Drda_CP_CMDATHRM      = 0x121C
const Drda_CP_AGNPRMRM      = 0x1232
const Drda_CP_RSCLMTRM      = 0x1233
const Drda_CP_PRCCNVRM      = 0x1245
const Drda_CP_CMDCMPRM      = 0x124B
const Drda_CP_SYNTAXRM      = 0x124C
const Drda_CP_CMDNSPRM      = 0x1250
const Drda_CP_PRMNSPRM      = 0x1251
const Drda_CP_VALNSPRM      = 0x1252
const Drda_CP_OBJNSPRM      = 0x1253
const Drda_CP_CMDCHKRM      = 0x1254
const Drda_CP_TRGNSPRM      = 0x125F
const Drda_CP_AGENT         = 0x1403
const Drda_CP_MGRLVLLS      = 0x1404
const Drda_CP_SUPERVISOR    = 0x143C
const Drda_CP_SECMGR        = 0x1440
const Drda_CP_EXCSATRD      = 0x1443
const Drda_CP_CMNAPPC       = 0x1444
const Drda_CP_DICTIONARY    = 0x1458
const Drda_CP_MGRLVLN       = 0x1473
const Drda_CP_CMNTCPIP      = 0x1474
const Drda_CP_FDODTA        = 0x147A
const Drda_CP_CMNSYNCPT     = 0x147C
const Drda_CP_ACCSECRD      = 0x14AC
const Drda_CP_SYNCPTMGR     = 0x14C0
const Drda_CP_RSYNCMGR      = 0x14C1
const Drda_CP_CCSIDMGR      = 0x14CC
const Drda_CP_MONITOR       = 0x1900
const Drda_CP_MONITORRD     = 0x1C00
const Drda_CP_XAMGR         = 0x1C01
const Drda_CP_ACCRDB        = 0x2001
const Drda_CP_BGNBND        = 0x2002
const Drda_CP_BNDSQLSTT     = 0x2004
const Drda_CP_CLSQRY        = 0x2005
const Drda_CP_CNTQRY        = 0x2006
const Drda_CP_DRPPKG        = 0x2007
const Drda_CP_DSCSQLSTT     = 0x2008
const Drda_CP_ENDBND        = 0x2009
const Drda_CP_EXCSQLIMM     = 0x200A
const Drda_CP_EXCSQLSTT     = 0x200B
const Drda_CP_OPNQRY        = 0x200C
const Drda_CP_PRPSQLSTT     = 0x200D
const Drda_CP_RDBCMM        = 0x200E
const Drda_CP_RDBRLLBCK     = 0x200F
const Drda_CP_REBIND        = 0x2010
const Drda_CP_DSCRDBTBL     = 0x2012
const Drda_CP_EXCSQLSET     = 0x2014
const Drda_CP_DSCERRCD      = 0x2101
const Drda_CP_QRYPRCTYP     = 0x2102
const Drda_CP_RDBINTTKN     = 0x2103
const Drda_CP_PRDDTA        = 0x2104
const Drda_CP_RDBCMTOK      = 0x2105
const Drda_CP_RDBCOLID      = 0x2108
const Drda_CP_PKGID         = 0x2109
const Drda_CP_PKGCNSTKN     = 0x210D
const Drda_CP_RTNSETSTT     = 0x210E
const Drda_CP_RDBACCCL      = 0x210F
const Drda_CP_RDBNAM        = 0x2110
const Drda_CP_OUTEXP        = 0x2111
const Drda_CP_PKGNAMCT      = 0x2112
const Drda_CP_PKGNAMCSN     = 0x2113
const Drda_CP_QRYBLKSZ      = 0x2114
const Drda_CP_UOWDSP        = 0x2115
const Drda_CP_RTNSQLDA      = 0x2116
const Drda_CP_RDBALWUPD     = 0x211A
const Drda_CP_SQLCSRHLD     = 0x211F
const Drda_CP_STTSTRDEL     = 0x2120
const Drda_CP_STTDECDEL     = 0x2121
const Drda_CP_PKGDFTCST     = 0x2125
const Drda_CP_QRYBLKCTL     = 0x2132
const Drda_CP_CRRTKN        = 0x2135
const Drda_CP_PRCNAM        = 0x2138
const Drda_CP_PKGSNLST      = 0x2139
const Drda_CP_NBRROW        = 0x213A
const Drda_CP_TRGDFTRT      = 0x213B
const Drda_CP_QRYRELSCR     = 0x213C
const Drda_CP_QRYROWNBR     = 0x213D
const Drda_CP_QRYRFRTBL     = 0x213E
const Drda_CP_MAXRSLCNT     = 0x2140
const Drda_CP_MAXBLKEXT     = 0x2141
const Drda_CP_RSLSETFLG     = 0x2142
const Drda_CP_TYPSQLDA      = 0x2146
const Drda_CP_OUTOVROPT     = 0x2147
const Drda_CP_RTNEXTDTA     = 0x2148
const Drda_CP_QRYATTSCR     = 0x2149
const Drda_CP_QRYATTUPD     = 0x2150
const Drda_CP_QRYSCRORN     = 0x2152
const Drda_CP_QRYROWSNS     = 0x2153
const Drda_CP_QRYBLKRST     = 0x2154
const Drda_CP_QRYRTNDTA     = 0x2155
const Drda_CP_QRYROWSET     = 0x2156
const Drda_CP_QRYATTSNS     = 0x2157
const Drda_CP_QRYINSID      = 0x215B
const Drda_CP_QRYCLSIMP     = 0x215D
const Drda_CP_QRYCLSRLS     = 0x215E
const Drda_CP_QRYOPTVAL     = 0x215F
const Drda_CP_DIAGLVL       = 0x2160
const Drda_CP_ACCRDBRM      = 0x2201
const Drda_CP_QRYNOPRM      = 0x2202
const Drda_CP_RDBNACRM      = 0x2204
const Drda_CP_OPNQRYRM      = 0x2205
const Drda_CP_PKGBNARM      = 0x2206
const Drda_CP_RDBACCRM      = 0x2207
const Drda_CP_BGNBNDRM      = 0x2208
const Drda_CP_PKGBPARM      = 0x2209
const Drda_CP_DSCINVRM      = 0x220A
const Drda_CP_ENDQRYRM      = 0x220B
const Drda_CP_ENDUOWRM      = 0x220C
const Drda_CP_ABNUOWRM      = 0x220D
const Drda_CP_DTAMCHRM      = 0x220E
const Drda_CP_QRYPOPRM      = 0x220F
const Drda_CP_RDBNFNRM      = 0x2211
const Drda_CP_OPNQFLRM      = 0x2212
const Drda_CP_SQLERRRM      = 0x2213
const Drda_CP_RDBUPDRM      = 0x2218
const Drda_CP_RSLSETRM      = 0x2219
const Drda_CP_RDBAFLRM      = 0x221A
const Drda_CP_CMDVLTRM      = 0x221D
const Drda_CP_CMMRQSRM      = 0x2225
const Drda_CP_RDBATHRM      = 0x22CB
const Drda_CP_SQLAM         = 0x2407
const Drda_CP_SQLCARD       = 0x2408
const Drda_CP_SQLCINRD      = 0x240B
const Drda_CP_SQLRSLRD      = 0x240E
const Drda_CP_RDB           = 0x240F
const Drda_CP_FRCFIXROW     = 0x2410
const Drda_CP_SQLDARD       = 0x2411
const Drda_CP_SQLDTA        = 0x2412
const Drda_CP_SQLDTARD      = 0x2413
const Drda_CP_SQLSTT        = 0x2414
const Drda_CP_OUTOVR        = 0x2415
const Drda_CP_LMTBLKPRC     = 0x2417
const Drda_CP_FIXROWPRC     = 0x2418
const Drda_CP_SQLSTTVRB     = 0x2419
const Drda_CP_QRYDSC        = 0x241A
const Drda_CP_QRYDTA        = 0x241B
const Drda_CP_CSTMBCS       = 0x2435
const Drda_CP_SRVLST        = 0x244E
const Drda_CP_SQLATTR       = 0x2450

const Drda_DSSFMT_SAME_CORR = 0x01
const Drda_DSSFMT_CONTINUE  = 0x02
const Drda_DSSFMT_CHAINED   = 0x04
const Drda_DSSFMT_RESERVED  = 0x08

const Drda_DSSFMT_RQSDSS    = 0x01
const Drda_DSSFMT_RPYDSS    = 0x02
const Drda_DSSFMT_OBJDSS    = 0x03
const Drda_DSSFMT_CMNDSS    = 0x04
const Drda_DSSFMT_NORPYDSS  = 0x05

const Drda_TEXT_DDM   = "DDM"
const Drda_TEXT_PARAM = "Parameter"

var drda_description = map[uint16]string {
	Drda_CP_DATA:         "Data" ,
    Drda_CP_CODPNT:       "Code Point" ,
    Drda_CP_FDODSC:       "FD:OCA Data Descriptor" ,
    Drda_CP_TYPDEFNAM:    "Data Type Definition Name" ,
    Drda_CP_TYPDEFOVR:    "TYPDEF Overrides" ,
    Drda_CP_CODPNTDR:     "Code Point Data Representation" ,
    Drda_CP_EXCSAT:       "Exchange Server Attributes" ,
    Drda_CP_SYNCCTL:      "Sync Point Control Request" ,
    Drda_CP_SYNCRSY:      "Sync Point Resync Command" ,
    Drda_CP_ACCSEC:       "Access Security" ,
    Drda_CP_SECCHK:       "Security Check" ,
    Drda_CP_SYNCLOG:      "Sync Point Log" ,
    Drda_CP_RSCTYP:       "Resource Type Information" ,
    Drda_CP_RSNCOD:       "Reason Code Information" ,
    Drda_CP_RSCNAM:       "Resource Name Information" ,
    Drda_CP_PRDID:        "Product-Specific Identifier" ,
    Drda_CP_PRCCNVCD:     "Conversation Protocol Error Code" ,
    Drda_CP_VRSNAM:       "Version Name" ,
    Drda_CP_SRVCLSNM:     "Server Class Name" ,
    Drda_CP_SVRCOD:       "Severity Code" ,
    Drda_CP_SYNERRCD:     "Syntax Error Code" ,
    Drda_CP_SRVDGN:       "Server Diagnostic Information" ,
    Drda_CP_SRVRLSLV:     "Server Product Release Level" ,
    Drda_CP_SPVNAM:       "Supervisor Name" ,
    Drda_CP_EXTNAM:       "External Name" ,
    Drda_CP_SRVNAM:       "Server Name" ,
    Drda_CP_SECMGRNM:     "Security Manager Name" ,
    Drda_CP_DEPERRCD:     "Manager Dependency Error Code" ,
    Drda_CP_CCSIDSBC:     "CCSID for Single-Byte Characters" ,
    Drda_CP_CCSIDDBC:     "CCSID for Double-byte Characters" ,
    Drda_CP_CCSIDMBC:     "CCSID for Mixed-byte Characters" ,
    Drda_CP_USRID:        "User ID at the Target System" ,
    Drda_CP_PASSWORD:     "Password" ,
    Drda_CP_SECMEC:       "Security Mechanism" ,
    Drda_CP_SECCHKCD:     "Security Check Code" ,
    Drda_CP_SVCERRNO:     "Security Service ErrorNumber" ,
    Drda_CP_SECTKN:       "Security Token" ,
    Drda_CP_NEWPASSWORD:  "New Password" ,
    Drda_CP_MGRLVLRM:     "Manager-Level Conflict" ,
    Drda_CP_MGRDEPRM:     "Manager Dependency Error" ,
    Drda_CP_SECCHKRM:     "Security Check" ,
    Drda_CP_CMDATHRM:     "Not Authorized to Command" ,
    Drda_CP_AGNPRMRM:     "Permanent Agent Error" ,
    Drda_CP_RSCLMTRM:     "Resource Limits Reached" ,
    Drda_CP_PRCCNVRM:     "Conversational Protocol Error" ,
    Drda_CP_CMDCMPRM:     "Command Processing Completed" ,
    Drda_CP_SYNTAXRM:     "Data Stream Syntax Error" ,
    Drda_CP_CMDNSPRM:     "Command Not Supported" ,
    Drda_CP_PRMNSPRM:     "Parameter Not Supported" ,
    Drda_CP_VALNSPRM:     "Parameter Value Not Supported" ,
    Drda_CP_OBJNSPRM:     "Object Not Supported" ,
    Drda_CP_CMDCHKRM:     "Command Check" ,
    Drda_CP_TRGNSPRM:     "Target Not Supported" ,
    Drda_CP_AGENT:        "Agent" ,
    Drda_CP_MGRLVLLS:     "Manager-Level List" ,
    Drda_CP_SUPERVISOR:   "Supervisor" ,
    Drda_CP_SECMGR:       "Security Manager" ,
    Drda_CP_EXCSATRD:     "Server Attributes Reply Data" ,
    Drda_CP_CMNAPPC:      "LU 6.2 Conversational Communications Manager" ,
    Drda_CP_DICTIONARY:   "Dictionary" ,
    Drda_CP_MGRLVLN:      "Manager-Level Number Attribute" ,
    Drda_CP_CMNTCPIP:     "TCP/IP CommunicationManager" ,
    Drda_CP_FDODTA:       "FD:OCA Data" ,
    Drda_CP_CMNSYNCPT:    "SNA LU 6.2 Sync Point Conversational Communications Manager" ,
    Drda_CP_ACCSECRD:     "Access Security Reply Data" ,
    Drda_CP_SYNCPTMGR:    "Sync Point Manager" ,
    Drda_CP_RSYNCMGR:     "ResynchronizationManager" ,
    Drda_CP_CCSIDMGR:     "CCSID Manager" ,
    Drda_CP_MONITOR:      "Monitor Events" ,
    Drda_CP_MONITORRD:    "Monitor Reply Data" ,
    Drda_CP_XAMGR:        "XAManager" ,
    Drda_CP_ACCRDB:       "Access RDB" ,
    Drda_CP_BGNBND:       "Begin Binding a Package to an RDB" ,
    Drda_CP_BNDSQLSTT:    "Bind SQL Statement to an RDB Package" ,
    Drda_CP_CLSQRY:       "Close Query" ,
    Drda_CP_CNTQRY:       "Continue Query" ,
    Drda_CP_DRPPKG:       "Drop RDB Package" ,
    Drda_CP_DSCSQLSTT:    "Describe SQL Statement" ,
    Drda_CP_ENDBND:       "End Binding a Package to an RDB" ,
    Drda_CP_EXCSQLIMM:    "Execute Immediate SQL Statement" ,
    Drda_CP_EXCSQLSTT:    "Execute SQL Statement" ,
    Drda_CP_OPNQRY:       "Open Query" ,
    Drda_CP_PRPSQLSTT:    "Prepare SQL Statement" ,
    Drda_CP_RDBCMM:       "RDB Commit Unit of Work" ,
    Drda_CP_RDBRLLBCK:    "RDB Rollback Unit of Work" ,
    Drda_CP_REBIND:       "Rebind an Existing RDB Package" ,
    Drda_CP_DSCRDBTBL:    "Describe RDB Table" ,
    Drda_CP_EXCSQLSET:    "Set SQL Environment" ,
    Drda_CP_DSCERRCD:     "Description Error Code" ,
    Drda_CP_QRYPRCTYP:    "Query Protocol Type" ,
    Drda_CP_RDBINTTKN:    "RDB Interrupt Token" ,
    Drda_CP_PRDDTA:       "Product-Specific Data" ,
    Drda_CP_RDBCMTOK:     "RDB Commit Allowed" ,
    Drda_CP_RDBCOLID:     "RDB Collection Identifier" ,
    Drda_CP_PKGID:        "RDB Package Identifier" ,
    Drda_CP_PKGCNSTKN:    "RDB Package Consistency Token" ,
    Drda_CP_RTNSETSTT:    "Return SET Statement" ,
    Drda_CP_RDBACCCL:     "RDB Access Manager Class" ,
    Drda_CP_RDBNAM:       "Relational Database Name" ,
    Drda_CP_OUTEXP:       "Output Expected" ,
    Drda_CP_PKGNAMCT:     "RDB Package Name and Consistency Token" ,
    Drda_CP_PKGNAMCSN:    "RDB Package Name, Consistency Token, and Section Number" ,
    Drda_CP_QRYBLKSZ:     "Query Block Size" ,
    Drda_CP_UOWDSP:       "Unit of Work Disposition" ,
    Drda_CP_RTNSQLDA:     "Maximum Result Set Count" ,
    Drda_CP_RDBALWUPD:    "RDB Allow Updates" ,
    Drda_CP_SQLCSRHLD:    "Hold Cursor Position" ,
    Drda_CP_STTSTRDEL:    "Statement String Delimiter" ,
    Drda_CP_STTDECDEL:    "Statement Decimal Delimiter" ,
    Drda_CP_PKGDFTCST:    "Package Default Character Subtype" ,
    Drda_CP_QRYBLKCTL:    "Query Block Protocol Control" ,
    Drda_CP_CRRTKN:       "Correlation Token" ,
    Drda_CP_PRCNAM:       "Procedure Name" ,
    Drda_CP_PKGSNLST:     "RDB Result Set Reply Message" ,
    Drda_CP_NBRROW:       "Number of Fetch or Insert Rows" ,
    Drda_CP_TRGDFTRT:     "Target Default Value Return" ,
    Drda_CP_QRYRELSCR:    "Query Relative Scrolling Action" ,
    Drda_CP_QRYROWNBR:    "Query Row Number" ,
    Drda_CP_QRYRFRTBL:    "Query Refresh Answer Set Table" ,
    Drda_CP_MAXRSLCNT:    "Maximum Result Set Count" ,
    Drda_CP_MAXBLKEXT:    "Maximum Number of Extra Blocks" ,
    Drda_CP_RSLSETFLG:    "Result Set Flags" ,
    Drda_CP_TYPSQLDA:     "Type of SQL Descriptor Area" ,
    Drda_CP_OUTOVROPT:    "Output Override Option" ,
    Drda_CP_RTNEXTDTA:    "Return of EXTDTA Option" ,
    Drda_CP_QRYATTSCR:    "Query Attribute for Scrollability" ,
    Drda_CP_QRYATTUPD:    "Query Attribute for Updatability" ,
    Drda_CP_QRYSCRORN:    "Query Scroll Orientation" ,
    Drda_CP_QRYROWSNS:    "Query Row Sensitivity" ,
    Drda_CP_QRYBLKRST:    "Query Block Reset" ,
    Drda_CP_QRYRTNDTA:    "Query Returns Datat" ,
    Drda_CP_QRYROWSET:    "Query Rowset Size" ,
    Drda_CP_QRYATTSNS:    "Query Attribute for Sensitivity" ,
    Drda_CP_QRYINSID:     "Query Instance Identifier" ,
    Drda_CP_QRYCLSIMP:    "Query Close Implicit" ,
    Drda_CP_QRYCLSRLS:    "Query Close Lock Release" ,
    Drda_CP_QRYOPTVAL:    "QRYOPTVAL" ,
    Drda_CP_DIAGLVL:      "SQL Error Diagnostic Level" ,
    Drda_CP_ACCRDBRM:     "Access to RDB Completed" ,
    Drda_CP_QRYNOPRM:     "Query Not Open" ,
    Drda_CP_RDBNACRM:     "RDB Not Accessed" ,
    Drda_CP_OPNQRYRM:     "Open Query Complete" ,
    Drda_CP_PKGBNARM:     "RDB Package Binding Not Active" ,
    Drda_CP_RDBACCRM:     "RDB Currently Accessed" ,
    Drda_CP_BGNBNDRM:     "Begin Bind Error" ,
    Drda_CP_PKGBPARM:     "RDB Package Binding Process Active" ,
    Drda_CP_DSCINVRM:     "Invalid Description" ,
    Drda_CP_ENDQRYRM:     "End of Query" ,
    Drda_CP_ENDUOWRM:     "End Unit of Work Condition" ,
    Drda_CP_ABNUOWRM:     "Abnormal End Unit ofWork Condition" ,
    Drda_CP_DTAMCHRM:     "Data Descriptor Mismatch" ,
    Drda_CP_QRYPOPRM:     "Query Previously Opened" ,
    Drda_CP_RDBNFNRM:     "RDB Not Found" ,
    Drda_CP_OPNQFLRM:     "Open Query Failure" ,
    Drda_CP_SQLERRRM:     "SQL Error Condition" ,
    Drda_CP_RDBUPDRM:     "RDB Update Reply Message" ,
    Drda_CP_RSLSETRM:     "RDB Result Set Reply Message" ,
    Drda_CP_RDBAFLRM:     "RDB Access Failed Reply Message" ,
    Drda_CP_CMDVLTRM:     "Command Violation" ,
    Drda_CP_CMMRQSRM:     "Commitment Request" ,
    Drda_CP_RDBATHRM:     "Not Authorized to RDB" ,
    Drda_CP_SQLAM:        "SQL Application Manager" ,
    Drda_CP_SQLCARD:      "SQL Communications Area Reply Data" ,
    Drda_CP_SQLCINRD:     "SQL Result Set Column Information Reply Data" ,
    Drda_CP_SQLRSLRD:     "SQL Result Set Reply Data" ,
    Drda_CP_RDB:          "Relational Database" ,
    Drda_CP_FRCFIXROW:    "Force Fixed Row Query Protocol" ,
    Drda_CP_SQLDARD:      "SQLDA Reply Data" ,
    Drda_CP_SQLDTA:       "SQL Program Variable Data" ,
    Drda_CP_SQLDTARD:     "SQL Data Reply Data" ,
    Drda_CP_SQLSTT:       "SQL Statement" ,
    Drda_CP_OUTOVR:       "Output Override Descriptor" ,
    Drda_CP_LMTBLKPRC:    "Limited Block Protocol" ,
    Drda_CP_FIXROWPRC:    "Fixed Row Query Protocol" ,
    Drda_CP_SQLSTTVRB:    "SQL Statement Variable Descriptions" ,
    Drda_CP_QRYDSC:       "Query Answer Set Description" ,
    Drda_CP_QRYDTA:       "Query Answer Set Data" ,
    Drda_CP_SQLATTR:      "SQL Statement Attributes" ,
}


var drda_abbrev = map[uint16]string {
	Drda_CP_DATA:          "DATA",
    Drda_CP_CODPNT:        "CODPNT",
    Drda_CP_FDODSC:        "FDODSC",
    Drda_CP_TYPDEFNAM:     "TYPDEFNAM",
    Drda_CP_TYPDEFOVR:     "TYPDEFOVR",
    Drda_CP_CODPNTDR:      "CODPNTDR",
    Drda_CP_EXCSAT:        "EXCSAT",
    Drda_CP_SYNCCTL:       "SYNCCTL",
    Drda_CP_SYNCRSY:       "SYNCRSY",
    Drda_CP_ACCSEC:        "ACCSEC",
    Drda_CP_SECCHK:        "SECCHK",
    Drda_CP_SYNCLOG:       "SYNCLOG",
    Drda_CP_RSCTYP:        "RSCTYP",
    Drda_CP_RSNCOD:        "RSNCOD",
    Drda_CP_RSCNAM:        "RSCNAM",
    Drda_CP_PRDID:         "PRDID",
    Drda_CP_PRCCNVCD:      "PRCCNVCD",
    Drda_CP_VRSNAM:        "VRSNAM",
    Drda_CP_SRVCLSNM:      "SRVCLSNM",
    Drda_CP_SVRCOD:        "SVRCOD",
    Drda_CP_SYNERRCD:      "SYNERRCD",
    Drda_CP_SRVDGN:        "SRVDGN",
    Drda_CP_SRVRLSLV:      "SRVRLSLV",
    Drda_CP_SPVNAM:        "SPVNAM",
    Drda_CP_EXTNAM:        "EXTNAM",
    Drda_CP_SRVNAM:        "SRVNAM",
    Drda_CP_SECMGRNM:      "SECMGRNM",
    Drda_CP_DEPERRCD:      "DEPERRCD",
    Drda_CP_CCSIDSBC:      "CCSIDSBC",
    Drda_CP_CCSIDDBC:      "CCSIDDBC",
    Drda_CP_CCSIDMBC:      "CCSIDMBC",
    Drda_CP_USRID:         "USRID",
    Drda_CP_PASSWORD:      "PASSWORD",
    Drda_CP_SECMEC:        "SECMEC",
    Drda_CP_SECCHKCD:      "SECCHKCD",
    Drda_CP_SVCERRNO:      "SVCERRNO",
    Drda_CP_SECTKN:        "SECTKN",
    Drda_CP_NEWPASSWORD:   "NEWPASSWORD",
    Drda_CP_MGRLVLRM:      "MGRLVLRM",
    Drda_CP_MGRDEPRM:      "MGRDEPRM",
    Drda_CP_SECCHKRM:      "SECCHKRM",
    Drda_CP_CMDATHRM:      "CMDATHRM",
    Drda_CP_AGNPRMRM:      "AGNPRMRM",
    Drda_CP_RSCLMTRM:      "RSCLMTRM",
    Drda_CP_PRCCNVRM:      "PRCCNVRM",
    Drda_CP_CMDCMPRM:      "CMDCMPRM",
    Drda_CP_SYNTAXRM:      "SYNTAXRM",
    Drda_CP_CMDNSPRM:      "CMDNSPRM",
    Drda_CP_PRMNSPRM:      "PRMNSPRM",
    Drda_CP_VALNSPRM:      "VALNSPRM",
    Drda_CP_OBJNSPRM:      "OBJNSPRM",
    Drda_CP_CMDCHKRM:      "CMDCHKRM",
    Drda_CP_TRGNSPRM:      "TRGNSPRM",
    Drda_CP_AGENT:         "AGENT",
    Drda_CP_MGRLVLLS:      "MGRLVLLS",
    Drda_CP_SUPERVISOR:    "SUPERVISOR",
    Drda_CP_SECMGR:        "SECMGR",
    Drda_CP_EXCSATRD:      "EXCSATRD",
    Drda_CP_CMNAPPC:       "CMNAPPC",
    Drda_CP_DICTIONARY:    "DICTIONARY",
    Drda_CP_MGRLVLN:       "MGRLVLN",
    Drda_CP_CMNTCPIP:      "CMNTCPIP",
    Drda_CP_FDODTA:        "FDODTA",
    Drda_CP_CMNSYNCPT:     "CMNSYNCPT",
    Drda_CP_ACCSECRD:      "ACCSECRD",
    Drda_CP_SYNCPTMGR:     "SYNCPTMGR",
    Drda_CP_RSYNCMGR:      "RSYNCMGR",
    Drda_CP_CCSIDMGR:      "CCSIDMGR",
    Drda_CP_MONITOR:       "MONITOR",
    Drda_CP_MONITORRD:     "MONITORRD",
    Drda_CP_XAMGR:         "XAMGR",
    Drda_CP_ACCRDB:        "ACCRDB",
    Drda_CP_BGNBND:        "BGNBND",
    Drda_CP_BNDSQLSTT:     "BNDSQLSTT",
    Drda_CP_CLSQRY:        "CLSQRY",
    Drda_CP_CNTQRY:        "CNTQRY",
    Drda_CP_DRPPKG:        "DRPPKG",
    Drda_CP_DSCSQLSTT:     "DSCSQLSTT",
    Drda_CP_ENDBND:        "ENDBND",
    Drda_CP_EXCSQLIMM:     "EXCSQLIMM",
    Drda_CP_EXCSQLSTT:     "EXCSQLSTT",
    Drda_CP_OPNQRY:        "OPNQRY",
    Drda_CP_PRPSQLSTT:     "PRPSQLSTT",
    Drda_CP_RDBCMM:        "RDBCMM",
    Drda_CP_RDBRLLBCK:     "RDBRLLBCK",
    Drda_CP_REBIND:        "REBIND",
    Drda_CP_DSCRDBTBL:     "DSCRDBTBL",
    Drda_CP_EXCSQLSET:     "EXCSQLSET",
    Drda_CP_DSCERRCD:      "DSCERRCD",
    Drda_CP_QRYPRCTYP:     "QRYPRCTYP",
    Drda_CP_RDBINTTKN:     "RDBINTTKN",
    Drda_CP_PRDDTA:        "PRDDTA",
    Drda_CP_RDBCMTOK:      "RDBCMTOK",
    Drda_CP_RDBCOLID:      "RDBCOLID",
    Drda_CP_PKGID:         "PKGID",
    Drda_CP_PKGCNSTKN:     "PKGCNSTKN",
    Drda_CP_RTNSETSTT:     "RTNSETSTT",
    Drda_CP_RDBACCCL:      "RDBACCCL",
    Drda_CP_RDBNAM:        "RDBNAM",
    Drda_CP_OUTEXP:        "OUTEXP",
    Drda_CP_PKGNAMCT:      "PKGNAMCT",
    Drda_CP_PKGNAMCSN:     "PKGNAMCSN",
    Drda_CP_QRYBLKSZ:      "QRYBLKSZ",
    Drda_CP_UOWDSP:        "UOWDSP",
    Drda_CP_RTNSQLDA:      "RTNSQLDA",
    Drda_CP_RDBALWUPD:     "RDBALWUPD",
    Drda_CP_SQLCSRHLD:     "SQLCSRHLD",
    Drda_CP_STTSTRDEL:     "STTSTRDEL",
    Drda_CP_STTDECDEL:     "STTDECDEL",
    Drda_CP_PKGDFTCST:     "PKGDFTCST",
    Drda_CP_QRYBLKCTL:     "QRYBLKCTL",
    Drda_CP_CRRTKN:        "CRRTKN",
    Drda_CP_PRCNAM:        "PRCNAM",
    Drda_CP_PKGSNLST:      "PKGSNLST",
    Drda_CP_NBRROW:        "NBRROW",
    Drda_CP_TRGDFTRT:      "TRGDFTRT",
    Drda_CP_QRYRELSCR:     "QRYRELSCR",
    Drda_CP_QRYROWNBR:     "QRYROWNBR",
    Drda_CP_QRYRFRTBL:     "QRYRFRTBL",
    Drda_CP_MAXRSLCNT:     "MAXRSLCNT",
    Drda_CP_MAXBLKEXT:     "MAXBLKEXT",
    Drda_CP_RSLSETFLG:     "RSLSETFLG",
    Drda_CP_TYPSQLDA:      "TYPSQLDA",
    Drda_CP_OUTOVROPT:     "OUTOVROPT",
    Drda_CP_RTNEXTDTA:     "RTNEXTDTA",
    Drda_CP_QRYATTSCR:     "QRYATTSCR",
    Drda_CP_QRYATTUPD:     "QRYATTUPD",
    Drda_CP_QRYSCRORN:     "QRYSCRORN",
    Drda_CP_QRYROWSNS:     "QRYROWSNS",
    Drda_CP_QRYBLKRST:     "QRYBLKRST",
    Drda_CP_QRYRTNDTA:     "QRYRTNDTA",
    Drda_CP_QRYROWSET:     "QRYROWSET",
    Drda_CP_QRYATTSNS:     "QRYATTSNS",
    Drda_CP_QRYINSID:      "QRYINSID",
    Drda_CP_QRYCLSIMP:     "QRYCLSIMP",
    Drda_CP_QRYCLSRLS:     "QRYCLSRLS",
    Drda_CP_QRYOPTVAL:     "QRYOPTVAL",
    Drda_CP_DIAGLVL:       "DIAGLVL",
    Drda_CP_ACCRDBRM:      "ACCRDBRM",
    Drda_CP_QRYNOPRM:      "QRYNOPRM",
    Drda_CP_RDBNACRM:      "RDBNACRM",
    Drda_CP_OPNQRYRM:      "OPNQRYRM",
    Drda_CP_PKGBNARM:      "PKGBNARM",
    Drda_CP_RDBACCRM:      "RDBACCRM",
    Drda_CP_BGNBNDRM:      "BGNBNDRM",
    Drda_CP_PKGBPARM:      "PKGBPARM",
    Drda_CP_DSCINVRM:      "DSCINVRM",
    Drda_CP_ENDQRYRM:      "ENDQRYRM",
    Drda_CP_ENDUOWRM:      "ENDUOWRM",
    Drda_CP_ABNUOWRM:      "ABNUOWRM",
    Drda_CP_DTAMCHRM:      "DTAMCHRM",
    Drda_CP_QRYPOPRM:      "QRYPOPRM",
    Drda_CP_RDBNFNRM:      "RDBNFNRM",
    Drda_CP_OPNQFLRM:      "OPNQFLRM",
    Drda_CP_SQLERRRM:      "SQLERRRM",
    Drda_CP_RDBUPDRM:      "RDBUPDRM",
    Drda_CP_RSLSETRM:      "RSLSETRM",
    Drda_CP_RDBAFLRM:      "RDBAFLRM",
    Drda_CP_CMDVLTRM:      "CMDVLTRM",
    Drda_CP_CMMRQSRM:      "CMMRQSRM",
    Drda_CP_RDBATHRM:      "RDBATHRM",
    Drda_CP_SQLAM:         "SQLAM",
    Drda_CP_SQLCARD:       "SQLCARD",
    Drda_CP_SQLCINRD:      "SQLCINRD",
    Drda_CP_SQLRSLRD:      "SQLRSLRD",
    Drda_CP_RDB:           "RDB",
    Drda_CP_FRCFIXROW:     "FRCFIXROW",
    Drda_CP_SQLDARD:       "SQLDARD",
    Drda_CP_SQLDTA:        "SQLDTA",
    Drda_CP_SQLDTARD:      "SQLDTARD",
    Drda_CP_SQLSTT:        "SQLSTT",
    Drda_CP_OUTOVR:        "OUTOVR",
    Drda_CP_LMTBLKPRC:     "LMTBLKPRC",
    Drda_CP_FIXROWPRC:     "FIXROWPRC",
    Drda_CP_SQLSTTVRB:     "SQLSTTVRB",
    Drda_CP_QRYDSC:        "QRYDSC",
    Drda_CP_QRYDTA:        "QRYDTA",
    Drda_CP_SQLATTR:       "SQLATTR",
}

var dss_abbrev = map[uint16]string {
    Drda_DSSFMT_RQSDSS:     "RQSDSS",
    Drda_DSSFMT_RPYDSS:     "RPYDSS",
    Drda_DSSFMT_OBJDSS:     "OBJDSS",
    Drda_DSSFMT_CMNDSS:     "CMNDSS",
    Drda_DSSFMT_NORPYDSS:   "NORPYDSS",
    0:          "NULL",
}