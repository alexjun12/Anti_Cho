import sys
import os
import hashlib
import zlib
import io
import scanmod

VirusDB = [] #파일크기:MD5 해시:악성코드 이름
vdb = [] #가공된 악성코드
vsize = [] #악성코드 파일크기 저장

def DecodeKMD(fname) : #KMD파일 복호화
    try :
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        buf2 = buf[:-32] #암호화 내용 분리
        fmd5 = buf[-32:] #md5 분리

        f = buf2
        for i in range(3) :
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest()

        if f != fmd5 :
            raise SystemError
        buf3 = ''
        for c in buf2[4:] : # 0xFF로 XOR한다
            buf3 += chr(ord(c) ^ 0xFF)

        buf4 = zlib.decompress(buf3) # 압축 해제
        return buf4 #성공했다면 복호화된 내용 반환
    except :
        pass

    return None #오류시 None반환

def LoadVirusDB() : #virus.db에서 악성코드 패턴 읽기
    buf = DecodeKMD('virus.kmd')
    fp = io.StringIO(buf)

    while(True) :
        line = fp.readline()
        if(not line) :
            break
        line = line.strip() #엔터키 제거
        VirusDB.append(line.decode('utf-8')) #받아온 byte타입 문자열로 디코딩

    fp.close()

def MakeVirusDB() : #악성코드 가공하여 vdb에 저장
    for pattern in VirusDB :
        temp = []
        v = pattern.split(':')
        temp.append(v[1])
        temp.append(v[2])
        vdb.append(temp)

        size = int(v[0])
        if(vsize.count(size) == 0) : #이미 해당 크기가 등록되었는가?
            vsize.append(size)


if __name__ == '__main__' :
    LoadVirusDB()
    MakeVirusDB()

    if(len(sys.argv) != 2) : #입력방식 체크
        print('Usage : antivirus.py [file]')
        exit(0)

    fname = sys.argv[1] #악성코드 검사 대상파일

    ret, vname = scanmod.ScanMD5(vdb, vsize, fname)
    if(ret == True) :
        print('%s : %s' % (fname,vname))
        os.remove(fname) #해당 파일 삭제
    else :
        print('%s : ok' % (fname))
