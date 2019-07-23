import os, sys

debug = int(ARGUMENTS.get('debug', 0))
iconv = ARGUMENTS.get('iconv', 'no')
pcre  = ARGUMENTS.get('pcre', 'no')
ssl   = ARGUMENTS.get('ssl', 'no')
sqlite= ARGUMENTS.get('sqlite', 'no')
mysql = ARGUMENTS.get('mysql', 'no')
msgpack  = ARGUMENTS.get('msgpack', 'no')
tcmalloc = ARGUMENTS.get('tcmalloc', 'no')
gc = ARGUMENTS.get('gc', 'no')
all = ARGUMENTS.get('gc', 'no')

name		= 'zocle'
version     = '2.0.1'
includes	= ['include', '/usr/local/include']
libs		= []
libpath		= ['.', '/usr/local/lib']
ldflags		= ''
ccflags     = '-std=gnu99 -Wall'

if debug:
	ccflags += ' -ggdb'

defs = [
	'_REENTRANT',
	'_GNU_SOURCE',
	# 'ZOCLE_WITH_LIBEV',
]

if iconv == 'yes' or all == 'yes':
	defs.append('ZOCLE_WITH_ICONV')
if pcre == 'yes' or all == 'yes':
	defs.append('ZOCLE_WITH_PCRE')
if ssl == 'yes' or all == 'yes':
	defs.append('ZOCLE_WITH_SSL')
if sqlite == 'yes' or all == 'yes':
	defs.append('ZOCLE_WITH_SQLITE')
if mysql == 'yes' or all == 'yes':
	defs.append('ZOCLE_WITH_MYSQL')
if msgpack == 'yes' or all == 'yes':
	defs.append('ZOCLE_WITH_MSGPACK')
if tcmalloc == 'yes' or all == 'yes':
	defs.append('ZOCLE_WITH_TCMALLOC')
if gc == 'yes':
	defs.append('ZOCLE_WITH_GC')



files = []
for root,dirs,fs in os.walk('src'):
	for d in dirs:
		if d == 'protocol' or 'protocol' in root:
			continue

		p = '%s/%s/*.c' % (root, d)
		files += Glob(p)

if sys.platform.startswith('win'):
	includes.append(os.path.join(msys_home, 'local/include'))
	libpath.append(os.path.join(msys_home, 'local/lib'))

if 'ZOCLE_WITH_SSL' in defs:
	if os.path.isdir('/usr/include/openssl'):
		print('use ssl at /usr/include/openssl')
	elif os.path.isdir('/usr/local/ssl'):
		print('use ssl at /usr/local/ssl')
		if sys.platform.startswith('win'):
			includes.append(os.path.join(msys_home, 'local/ssl/include'))
			libpath.append(os.path.join(msys_home, 'local/ssl/lib'))
		else:
			includes.append('/usr/local/ssl/include')
			libpath.append('/usr/local/ssl/lib')
	if os.path.isdir('/usr/local/opt/openssl'):
		print('use ssl at /usr/local/opt/openssl/')
		includes.append('/usr/local/opt/openssl/include')
		libpath.append('/usr/local/opt/openssl/lib')
	else:
		print('no ssl dir, use system')
	libs.append('ssl')
	libs.append('crypto')

if 'ZOCLE_WITH_ICONV' in defs:
	libs.append('iconv')

if 'ZOCLE_WITH_PCRE' in defs:
	libs.append('pcre')

if 'ZOCLE_WITH_LIBEV' in defs:
	libs.append('ev')

if 'ZOCLE_WITH_MYSQL' in defs:
	libs.append('mysqlclient')
	if os.path.isdir('/usr/local/mysql'):
		includes.append('/usr/local/mysql/include')
		libpath.append('/usr/local/mysql/lib')
	elif os.path.isdir('/usr/include/mysql'):
		includes.append('/usr/include/mysql')

if 'ZOCLE_WITH_SQLITE' in defs:
	libs.append('sqlite3')

if 'ZOCLE_WITH_TCMALLOC' in defs:
	libs.append('tcmalloc_minimal')

if 'ZOCLE_WITH_GC' in defs:
	libs.append('gc')

env = Environment(CCFLAGS=ccflags,
            CPPDEFINES=defs, CPPPATH=includes,
            LIBPATH=libpath, LIBS=libs, LINKFLAGS=ldflags)

env.StaticLibrary(name, files)
env.SharedLibrary(name, files, SHLIBVERSION=version)

#SConscript('test/SConstruct', exports=['defs', 'includes', 'libpath', 'libs'])

