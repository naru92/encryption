# encryption
## 암호화 알고리즘에는 크게 단방향, 양방향 암호화가 있다.

-- 

1. 단방향
단방향 암호화는 암호화 시키면 복호화 시킬수 없는걸 말한다.
복원방법이 없으므로 원래 어떤 문자였는지 알 수 없다.

종류: MD5, SHA1, SHA2(권장)
이러한 단방향 암호화는 패스워드 정보에 주로 사용한다.
SHA2 중에서도 SHA256 이상을 권장한다. 

2. 양방향 
양방향 암호화는 데이터 통신에 주로 사용한다.
은행거래나 결제시스템 이용시 중요한 정보들을 교환할때

종류: 양방향(대칭키) 암호화에는 DES, AES
      AES는 192이상을 권장한다.
      
      양방향(비대칭키) 암호화에는 대표적으로 RSA가 있다.
 



