import string, os

home = 'include/zocle/'
dirs = os.listdir("include")
f = open("include/zocle/zocle.h", 'w')
f.write('#ifndef ZOCLE_H\n#define ZOCLE_H\n\n')
f.write('#ifdef __cplusplus\nextern "C" {\n#endif\n\n')

def create_header():
    for d in dirs:
        if not os.path.isdir(home + d):
            continue
        files = os.listdir(home + d)
        for fn in files:
            if fn == 'atomic.h':
                continue
            if fn[-2:] == '.h' and os.path.isfile(home + d + os.sep + fn):
                f.write('#include <zocle/%s/%s>\n' % (d, fn))

def create_header2():
    for root,dirs,files in os.walk('include/zocle'):
        for fn in files:
            path = os.path.join(root, fn)
            if path.endswith('zocle.h'):
                continue
            if path.startswith('.'):
                continue
            if not path.endswith(('.h')):
                continue
            #print path, path[len('include/'):]
            f.write('#include <%s>\n' % path[len('include/'):])

create_header2()

#f.write('\nextern int z_init();\n')
f.write('\n#ifdef __cplusplus\n}\n#endif\n\n')
f.write('\n#endif\n')
f.close()

