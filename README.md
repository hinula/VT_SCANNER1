# 🛡️ Enterprise VT Scanner - Kurumsal Güvenlik Analizi Platformu

## 📋 Proje Özeti

Enterprise VT Scanner, kurumsal ihtiyaçlar için özel olarak tasarlanmış, gelişmiş güvenlik analizi platformudur. Kullanıcıların şüpheli dosyalarını güvenle yükleyip, 70+ antivirüs motoru ile kapsamlı analiz yapabilmelerini sağlar. Sonuçlar profesyonel PDF raporları halinde sunulur.

## ✨ Özellikler

### 🔒 Güvenlik
- **End-to-End Şifreleme**: Dosya transferi sırasında maksimum güvenlik
- **Güvenli Dosya İşleme**: AWS altyapısı ile güvenli dosya saklama
- **SSL Sertifikası**: Tüm iletişim HTTPS üzerinden şifrelenir

### 🚀 Performans
- **Hızlı Analiz**: Gelişmiş algoritmalar ile saniyeler içinde sonuç
- **Ölçeklenebilir Altyapı**: AWS Lambda ile otomatik ölçeklendirme
- **Gerçek Zamanlı İzleme**: Analiz sürecini canlı takip etme

### �� Raporlama
- **Profesyonel PDF Raporları**: Kurumsal standartlarda detaylı raporlar
- **Analitik Veriler**: Güvenlik skorları ve istatistikler
- **Çoklu Format Desteği**: Tüm dosya türlerini destekler

## 🏗️ Teknik Mimari

### Frontend
- **HTML5 + CSS3**: Modern, responsive tasarım
- **Vanilla JavaScript**: Framework bağımsız, hızlı performans
- **Font Awesome**: Profesyonel ikonlar
- **Inter Font**: Okunabilir tipografi

### Backend
- **AWS Lambda**: Serverless işlem gücü
- **API Gateway**: RESTful API endpoint'leri
- **S3 Storage**: Güvenli dosya saklama
- **DynamoDB**: Hızlı veri erişimi

### Entegrasyon
- **VirusTotal API**: 70+ antivirüs motoru entegrasyonu
- **AWS SDK**: Boto3 ile AWS servisleri
- **ReportLab**: PDF rapor oluşturma

## 🚀 Kurulum ve Deployment

### Gereksinimler
- AWS Hesabı
- Python 3.9+
- VirusTotal API Anahtarı

### Frontend Deployment (Vercel)
```bash
# Projeyi klonlayın
git clone [repository-url]
cd vt-scanner-frontend

# Vercel'e deploy edin
vercel --prod
```

### Backend Deployment (AWS)
```bash
# Lambda Layer oluşturun
pip install -r requirements.txt -t python/
zip -r lambda-layer.zip python/

# CloudFormation template'ini deploy edin
aws cloudformation create-stack \
  --stack-name vt-scanner-stack \
  --template-body file://cloudformation-template.yaml \
  --capabilities CAPABILITY_IAM
```

## 📱 Kullanım

### 1. Dosya Yükleme
- Dosyayı sürükleyip bırakın veya tıklayarak seçin
- Maksimum dosya boyutu: 32MB
- Desteklenen formatlar: Tüm dosya türleri

### 2. Güvenlik Analizi
- "Güvenlik Analizini Başlat" butonuna tıklayın
- Dosya AWS'e yüklenir ve VirusTotal'a gönderilir
- Analiz süreci gerçek zamanlı takip edilir

### 3. Sonuçları Görüntüleme
- Analiz tamamlandığında detaylı sonuçlar gösterilir
- Güvenlik skorları ve istatistikler sunulur
- PDF raporu indirilebilir

## �� Konfigürasyon

### Environment Variables
```bash
VIRUSTOTAL_API_KEY=your_api_key_here
S3_BUCKET=your_s3_bucket_name
DYNAMODB_TABLE=your_dynamodb_table_name
AWS_REGION=eu-central-1
```

### API Endpoints
- `POST /vt-scanner` - Ana endpoint
- Actions: `upload_file`, `scan_file`, `get_scan_status`, `download_report`

## 📊 Güvenlik Özellikleri

### Dosya Güvenliği
- **Hash Doğrulama**: SHA-256 ile dosya bütünlüğü
- **Boyut Limiti**: 32MB maksimum dosya boyutu
- **Format Kontrolü**: Tüm dosya türleri desteklenir

### API Güvenliği
- **CORS Koruması**: Cross-origin istekler kontrol edilir
- **Rate Limiting**: API kullanımı sınırlandırılır
- **Input Validation**: Tüm girişler doğrulanır

## �� Test

### Frontend Test
```bash
# Tarayıcıda test edin
https://your-vercel-app.vercel.app
```

### Backend Test
```bash
# Lambda test event'i
{
  "action": "upload_file",
  "file_content": "base64_encoded_content",
  "file_name": "test.txt",
  "file_size": 1024
}
```

## 📈 Performans Metrikleri

- **Dosya Yükleme**: < 5 saniye (32MB dosya)
- **Analiz Süresi**: 10-30 saniye (dosya boyutuna bağlı)
- **PDF Rapor**: < 3 saniye
- **Uptime**: %99.9 AWS SLA

## 🔍 Monitoring ve Logging

### CloudWatch Logs
- Lambda fonksiyon logları
- API Gateway erişim logları
- Hata takibi ve analizi

### Metrics
- Dosya yükleme sayısı
- Analiz başarı oranı
- API response time
- Hata oranları

## �� Hata Yönetimi

### Yaygın Hatalar
- **CORS Hatası**: API Gateway CORS ayarlarını kontrol edin
- **Lambda Timeout**: Memory ve timeout değerlerini artırın
- **S3 Permission**: IAM rollerini doğrulayın

### Troubleshooting
```bash
# CloudWatch loglarını kontrol edin
aws logs describe-log-groups
aws logs filter-log-events --log-group-name /aws/lambda/vt-scanner
```

## 💰 Maliyet Analizi

### AWS Servisleri (Aylık)
- **Lambda**: ~$5-15 (1000 istek/gün)
- **S3**: ~$2-5 (100GB depolama)
- **DynamoDB**: ~$3-8 (1M okuma/yazma)
- **API Gateway**: ~$1-3 (1M istek)

### Toplam Tahmini Maliyet: $11-31/ay

## 🔮 Gelecek Geliştirmeler

### Kısa Vadeli (1-3 ay)
- [ ] Batch dosya analizi
- [ ] Email rapor gönderimi
- [ ] Webhook entegrasyonları

### Orta Vadeli (3-6 ay)
- [ ] Mobile uygulama
- [ ] API rate limiting
- [ ] Advanced analytics dashboard

### Uzun Vadeli (6+ ay)
- [ ] Machine learning entegrasyonu
- [ ] Multi-tenant architecture
- [ ] Enterprise SSO

## �� Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push yapın (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📞 İletişim

- **Email**: serverless.vt@gmail.com
- **Adres**: İstanbul, Türkiye
- **Website**: https://vt-scanner-1.vercel.app/

## 🙏 Teşekkürler

- [VirusTotal](https://www.virustotal.com/) - Antivirüs API servisleri
- [AWS](https://aws.amazon.com/) - Cloud altyapı
- [Vercel](https://vercel.com/) - Frontend hosting
- [Font Awesome](https://fontawesome.com/) - İkonlar

---

**⚠️ Önemli Not**: Bu platform sadece eğitim ve test amaçlı kullanılmalıdır. Üretim ortamında kullanmadan önce güvenlik testlerini tamamlayın.

**�� Son Güncelleme**: 25 Ağustos 2024
**�� Versiyon**: 1.0.0
**�� Python**: 3.9+
**☁️ AWS**: Lambda, S3, DynamoDB, API Gateway
