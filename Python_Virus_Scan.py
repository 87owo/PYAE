import os, hashlib, requests
from PE_Model import function_list
from pefile import PE

def get_md5(file_path):#使用MD5较验掃描
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:#读取文件
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        response = requests.get("http://27.147.30.238:5001/pyas", params={'md5': str(hash_md5.hexdigest())}, timeout=2)
        return response.status_code == 200 and response.text == "True"#连接到PYAS云端服务器，回传True表示有毒，超时2秒自动跳过
    except:
        return False

def get_pe(file_path):#使用PE函數掃描
    try:
        fn = []
        pe = PE(file_path)#读取文件
        pe.close()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                fn.append(str(func.name, "utf-8"))
        for vfl in function_list:#检查病毒相符程度，在0.0~1.0之间，数字越大误杀越少，数字越少查杀越高，推荐值1.0
            return (sum(1 for num in fn if num in vfl)/len(vfl)) - (sum(1 for num in fn if num not in vfl)/len(vfl)) == 1.0
    except:
        return False

def scan_directory(path,suspicious_files):
    for root, dirs, files in os.walk(path):
        for file in files:#遍历文件路径
            try:#使用Try来应对突发情况
                file_path = os.path.join(root, file)
                if get_pe(file_path):
                    suspicious_files.append(file_path)
                elif get_md5(file_path):
                    suspicious_files.append(file_path)
            except:
                pass
    return suspicious_files

if __name__ == '__main__':
    suspicious_files = scan_directory(input('输入需要扫描的目录: '),[])#改用输入目录方式，不须频繁修改程式码
    if not suspicious_files:#列表空的，无病毒
        print('没有发现病毒。')
    else:
        print('以下文件怀疑是病毒：')#列表有数据，有病毒
        for file in suspicious_files:
            print(file)
