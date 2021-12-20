import sys
import os
import hashlib

VirusDB = [] #파일크기:MD5 해시:악성코드 이름
vdb = [] #가공된 악성코드
vsize = [] #악성코드 파일크기 저장

def LoadVirusDB() : #virus.db에서 악성코드 패턴 읽기
    fp = open('virus.db', 'rb')

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

def SearchVDB(fmd5) : #악성코드 검사
    for temp in vdb :
        if temp[0] == fmd5 : #md5해시가 같은지 비교
            return True, temp[1]

    return False, '' #악성코드 발견되지 않음

if __name__ == '__main__' :
    LoadVirusDB()
    MakeVirusDB()

    if(len(sys.argv) != 2) : #입력방식 체크
        print('Usage : antivirus.py [file]')
        exit(0)

    fname = sys.argv[1] #악성코드 검사 대상파일
    size = os.path.getsize(fname)
    if(vsize.count(size)) :
        fp = open(fname, 'rb') #바이너리 모드로 읽기
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest() #문자열로 변환

        ret, vname = SearchVDB(fmd5)
        if(ret == True) :
            print('%s : %s' % (fname,vname))
            os.remove(fname) #해당 파일 삭제
        else :
            print('%s : ok' % (fname))
    else :
        print('%s : ok' % (fname))

