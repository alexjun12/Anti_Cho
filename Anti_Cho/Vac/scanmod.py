import os
import hashlib

def SearchVDB(vdb, fmd5) : #악성코드 검사
    for temp in vdb :
        if temp[0] == fmd5 : #md5해시가 같은지 비교
            return True, temp[1]

    return False, '' #악성코드 발견되지 않음

def ScanMD5(vdb, vsize, fname) :
    ret = False #악성코드 발견 유무
    vname = '' #발견된 악성코드 명

    size = os.path.getsize(fname)
    if(vsize.count(size)) :
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(vdb, fmd5) #악성코드 검사

    return ret, vname