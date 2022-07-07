from hashlib import md5
from pefile import PE
from tkinter import filedialog

def file_scan(file):
    print('正在初始化，請稍後...')
    with open('Library/Viruslist.md5','r') as fp:#初始化MD5資料庫
        rfp = fp.read()
    with open('Library/Viruslist.func','r') as fn:#初始化函式資料庫
        rfn = fn.read()
    print('PYAE 正在掃描中，請稍後...')
    print('----------------------------------------')
    if file != "":#空白資料檢測
        if md5_scan(file,rfp):#執行MD5資料檢測
            print('掃描結果: 惡意文件 (強烈建議立即刪除此檔案)')
        else:#若MD5沒檢測到
            try:#嘗試
                fts = 0
                pe = PE(file)#讀取PE
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for function in entry.imports:#讀取函式
                        if str(function.name) in rfn:#如果有出現在料庫內
                            fts = fts + 1#添加1
                if fts != 0:#如果有出現
                    fts = 0#重置
                    print('掃描結果: 危險文件 (此檔案可能會修改部分系統功能)')
                else:#如果都沒有
                    print('掃描結果: 安全文件 (當前未找到含有惡意內容)')
            except Exception as e:#如果非執行檔案
                print('掃描結果: 安全文件 (當前未找到含有惡意內容)')
        fp.close()#關閉MD5資料庫
        fn.close()#關閉函式資料庫
    else:
        pass

def md5_scan(file,rfp):#定義MD5資料檢測
    try:#嘗試
        virus_found = False
        with open(file,"rb") as f:#與需要掃描的檔案做對比
            bytes = f.read()
            readable_hash = md5(bytes).hexdigest();
            if str(readable_hash) in str(rfp):#如果有出現在料庫內
                virus_found = True#將此檔案設為病毒
                f.close()
        if not virus_found:#如果不是病毒
            return False#回傳False
        else:#否則
            return True#回傳True
    except:#異常略過
        pass

def check_key():#定義自我安全檢查
    print('正在進行自我安全檢查，請稍後...')
    file = 'PYAE.py'#檢查的項目
    if file != '':#空白資料檢測
        with open(file,"rb") as f:#開起檢查的項目
            bytes = f.read()#讀取Bytes
            readable_hash = md5(bytes).hexdigest();#讀取 MD5 HASHES
        f.close()#關閉檢查的項目
        try:#嘗試
            ft = open('Library/PYAE.key','r')#開啟對比文件
            fe = ft.read()#讀取文件值
            ft.close()#關閉對比文件
            if fe == readable_hash:#如果與對比文件數據相同
                print('安全檢查通過: 您可以放心使用 PYAE 掃毒引擎。')
                print('----------------------------------------')
                print('請選擇需要掃描的檔案。')
                file = filedialog.askopenfilename()#TK選擇掃描檔案
                if file != '':#空白資料檢測
                    file_scan(file)#執行掃毒引擎
                else:#否則略過
                    print('未選擇任何檔案。')
            else:#否則略過
                print('安全檢查錯誤: 當前 PYAE 掃毒引擎不是正版，或被修改過，為了保證您的數據安全，請從官方提供的載點重新下載。')
        except:#異常略過
            print('安全檢查錯誤: 當前 PYAE 掃毒引擎安全密鑰缺失，為了保證您的數據安全，請從官方提供的載點重新下載。')
    else:
        pass

print('掃毒引擎版本: PYAE V1.2.3')
print('由 PYDT 安全開發團隊製作')
print('----------------------------------------')
check_key()#執行自我安全檢查
