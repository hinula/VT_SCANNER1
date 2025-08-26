# Enterprise VT Scanner

Enterprise VT Scanner, kurumsal güvenlik ihtiyaçları için tasarlanmış gelişmiş bir dosya analiz platformudur. Platform, yüklenen dosyaları kapsamlı bir şekilde analiz eder, güvenlik risklerini tespit eder ve profesyonel PDF raporları sunar. Web uygulaması Vercel üzerinde barındırılmakta olup, AWS altyapısı ile serverless olarak çalışmaktadır.  

Web sitesi: [vt-scanner-1.vercel.app](https://vt-scanner-1.vercel.app/)

---

## Özellikler

- Hızlı Analiz: Dosyalar saniyeler içinde taranır.
- Maksimum Güvenlik: End-to-end şifreleme ve güvenli dosya işleme.
- Detaylı Raporlama: Profesyonel PDF raporları ve analitik veriler.
- Cloud Native: AWS altyapısı ile ölçeklenebilir ve güvenilir.
- API Desteği: Kurumsal entegrasyonlar için hazır API.

---

## Teknolojiler

- Frontend: HTML, CSS, JavaScript
- Backend: AWS Lambda, Vercel Serverless Functions
- Depolama ve Veri Yönetimi: AWS S3, AWS DynamoDB
- Güvenlik ve Anahtar Yönetimi: AWS Secrets Manager
- Virüs Analizi: VirusTotal API

---

## Kullanım

1. Web sitesini ziyaret edin: [vt-scanner-1.vercel.app](https://vt-scanner-1.vercel.app/)
2. Dosyanızı seçin veya sürükleyin.
3. "Güvenlik Analizini Başlat" butonuna tıklayın.
4. Analiz ilerleme çubuğunu takip edin.
5. Analiz tamamlandığında detaylı sonuçları görüntüleyin ve PDF raporu indirin.

---

## AWS Altyapısı ve Mimari

Enterprise VT Scanner, AWS servisleri ve serverless mimari ile ölçeklenebilir, güvenli ve yüksek performanslı bir platform olarak tasarlanmıştır.

### Mimari Diyagram

[ Kullanıcı / Browser ]
|
v
[ Vercel Frontend ] ----> [ AWS Lambda Functions ]
| |
| v
| [ VirusTotal API ]
| |
v v
[ S3 Storage ] <-------- [ DynamoDB ]
|
v
[ PDF Raporlama ,
] 
### AWS Servisleri

1. **Vercel Serverless Frontend**  
   - Kullanıcı arayüzü ve dosya yükleme işlemleri.  
   - Modern responsive tasarım.

2. **AWS Lambda**  
   - Dosya yükleme, VirusTotal API çağrısı ve veri işleme.  
   - Serverless yapı ile ölçeklenebilir ve düşük maliyetli çözüm.

3. **AWS S3**  
   - Yüklenen dosyaların güvenli şekilde depolanması.  
   - PDF raporlarının geçici veya kalıcı saklanması.

4. **AWS DynamoDB**  
   - Tarama sonuçları ve metadata yönetimi.  
   - Hızlı sorgulama ve güvenli veri depolama.

5. **AWS Secrets Manager**  
   - API anahtarlarının güvenli yönetimi.  
   - VirusTotal API ve diğer hassas bilgiler burada tutulur.

6. **VirusTotal API**  
   - Dosya tarama ve zararlı yazılım tespiti.  
   - 70+ antivirüs motoru ile yüksek doğruluk.

7. **PDF Raporlama**  
   - Tarama sonuçları detaylı şekilde PDF formatında hazırlanır.  
   - Kullanıcılar tek tıkla PDF raporunu indirebilir.

---

## Güvenlik

- SSL/TLS ile güvenli bağlantı
- End-to-end şifreleme
- ISO 27001 ve GDPR uyumlu altyapı
- API anahtarları ve kritik veriler AWS Secrets Manager ile korunur

---

## Katkı

Bu proje, kurumsal güvenlik analizi ve dosya tarama çözümleri geliştirmek isteyen geliştiriciler için örnek teşkil etmektedir.

---

