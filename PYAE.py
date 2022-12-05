from pefile import PE, DIRECTORY_ENTRY
import os

def pyas_sign_start(file):
    try:
        pe = PE(file,fast_load=True)
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress == 0:
            pe.close()
            return True
        else:
            pe.close()
            return False
    except:
        return False

def path_scan_start(path,sfile,ufile):
    try:
        for fd in os.listdir(path):
            try:
                fullpath = str(os.path.join(path,fd))
                if 'C:/Windows' not in path:
                    if os.path.isdir(fullpath):
                        path_scan_start(fullpath,sfile,ufile)
                    else:
                        afile.append(fullpath)
                        root, extension = os.path.splitext(fd)
                        if '.exe' in extension.lower():
                            if pyas_sign_start(fullpath):
                                ufile.append(fullpath)
                                print('Unauthenticated file: '+fullpath)
                            else:
                                sfile.append(fullpath)
            except:
                continue
    except:
        pass

afile = []
sfile = []
ufile = []
input('Signature Detection Tool V1.0 (Press Enter to start)\n'+('='*60))
path_scan_start('A:/',sfile,ufile)
path_scan_start('B:/',sfile,ufile)
path_scan_start('C:/',sfile,ufile)
path_scan_start('D:/',sfile,ufile)
path_scan_start('E:/',sfile,ufile)
path_scan_start('F:/',sfile,ufile)
path_scan_start('G:/',sfile,ufile)
path_scan_start('H:/',sfile,ufile)
path_scan_start('I:/',sfile,ufile)
path_scan_start('J:/',sfile,ufile)
path_scan_start('K:/',sfile,ufile)
path_scan_start('L:/',sfile,ufile)
path_scan_start('M:/',sfile,ufile)
path_scan_start('N:/',sfile,ufile)
path_scan_start('O:/',sfile,ufile)
path_scan_start('P:/',sfile,ufile)
path_scan_start('Q:/',sfile,ufile)
path_scan_start('R:/',sfile,ufile)
path_scan_start('S:/',sfile,ufile)
path_scan_start('T:/',sfile,ufile)
path_scan_start('U:/',sfile,ufile)
path_scan_start('V:/',sfile,ufile)
path_scan_start('W:/',sfile,ufile)
path_scan_start('X:/',sfile,ufile)
path_scan_start('Y:/',sfile,ufile)
path_scan_start('Z:/',sfile,ufile)
print(('='*60)+'\nScanned files: '+str(len(afile))+'\nDetected files: '+str(len(sfile)+len(ufile))+'\nCertified file: '+str(len(sfile))+'\nUncertified file: '+str(len(ufile)))
input(('='*60)+'\nPowered by PYAS, press Enter to end the program')
