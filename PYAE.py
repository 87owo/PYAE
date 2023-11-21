import pefile, os, gc
from PYAS_Function import function_list
from PYAS_Function_Safe import function_list_safe

def pe_scan(file):
    try:
        fn = []
        with pefile.PE(file) as pe:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        try:
                            fn.append(str(func.name, "utf-8"))
                        except:
                            pass
                max_vfl = []
                for vfl in function_list:
                    max_vfl.append(len(set(fn)&set(vfl))/len(set(fn)|set(vfl)))
                max_sfl = []
                for sfl in function_list_safe:
                    max_sfl.append(len(set(fn)&set(sfl))/len(set(fn)|set(sfl)))
                if max(max_vfl) == 1.0 and max(max_sfl) != 1.0:
                    print(f'Engine: PYAS ML Engine\nDetect: Virus\nLevels: {max(max_vfl)}/{max(max_sfl)}\nFile: {file}\n{"="*50}')
                elif max(max_vfl) - max(max_sfl) >= 0.1:
                    print(f'Engine: PYAS ML Engine\nDetect: Suspicious\nLevels: {max(max_vfl)}/{max(max_sfl)}\nFile: {file}\n{"="*50}')
                elif max(max_sfl) - max(max_vfl) >= 0.1:
                    print(f'Engine: PYAS ML Engine\nDetect: Safe\nLevels: {max(max_vfl)}/{max(max_sfl)}\nFile: {file}\n{"="*50}')
                else:
                    print(f'Engine: PYAS ML Engine\nDetect: Warning\nLevels: {max(max_vfl)}/{max(max_sfl)}\nFile: {file}\n{"="*50}')
            else:
                print(f'Engine: PYAS ML Engine\nDetect: Unknown\nLevels: 0.0/0.0\nFile: {file}\n{"="*50}')
    except:
        pass

def traverse_path(path):
    try:
        if os.path.isfile(path):
            pe_scan(path)
        else:
            for fd in os.listdir(path):
                try:
                    file = str(os.path.join(path,fd))
                    if os.path.isdir(file):
                        traverse_path(file)
                    elif ":\\Windows" not in file:
                        pe_scan(file)
                        gc.collect()
                except:
                    pass
    except:
        pass

path = input("Input Scan Path or File: ")
print("="*50)
traverse_path(path)
input("Press Enter To Quit")
