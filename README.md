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

###Kullanıcı / Browser 
###  |
###  v
###Vercel Frontend ---->  AWS Lambda Functions 
###  |                             |
###  |                             v
###  |                        VirusTotal API 
###  |                             |
###  v                             v
###S3 Storage  <--------          DynamoDB 
###  |
###  v
###PDF Raporlama 


### AWS Servisleri

1. **Vercel Serverless Frontend**  
   - Kullanıcı arayüzü ve dosya yükleme işlemleri.  
   - Modern responsive tasarım.

2. **AWS Lambda**  
   - Dosya yükleme, VirusTotal API çağrısı ve veri işleme.  
   - Serverless yapı ile ölçeklenebilir ve düşük maliyetli çözüm.
   - ## Lambda Function

Aşağıdaki Python kodu AWS Lambda üzerinde çalışacak olan `lambda_function.py` dosyasıdır:

```python
# lambda_function.py
import json
import boto3
import hashlib
import os
import time
import base64
from datetime import datetime
from botocore.exceptions import ClientError
from decimal import Decimal

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)   # JSON için Decimal → float
        return super(DecimalEncoder, self).default(obj)

# requests tercih ediliyor (multipart ve timeout kolay)
try:
    import requests
except Exception:
    requests = None

# AWS clients
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

# ENV (Lambda'da ayarlı olmalı)
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
S3_BUCKET = os.environ.get('S3_BUCKET')
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE')
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/vtapi/v2'

# Küresel CORS header (özelleştir)
DEFAULT_CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Origin,Accept',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS,PUT,DELETE',
    'Access-Control-Allow-Credentials': 'true'
}

def lambda_handler(event, context):
    def lambda_handler(event, context):
    """
    Genel entry point. API Gateway (proxy) veya doğrudan invoke destekler.
    Beklenen POST body (JSON) örneği:
    {
      "action": "upload_file",
      "file_name": "example.exe",
      "file_size": 12345,
      "file_content": "<base64-string>"
    }
    veya
    {
      "action": "scan_file",
      "scan_id": "scan_..."
    }
    """
    headers = DEFAULT_CORS_HEADERS.copy()
    try:
        # Parse body: API Gateway proxy v1/v2 veya doğrudan event
        body = {}
        if 'body' in event:
            raw = event['body']
            if event.get('isBase64Encoded'):
                try:
                    raw = base64.b64decode(raw).decode('utf-8')
                except Exception as e:
                    print("isBase64Encoded decode hata:", repr(e))
                    return create_response(400, {'error': 'body base64 decode edilemedi'}, headers)
            if raw:
                try:
                    body = json.loads(raw)
                except Exception as e:
                    print("JSON parse hatası:", repr(e))
                    return create_response(400, {'error': 'body JSON değil'}, headers)
        else:
            # doğrudan invoke ederken event zaten JSON olabilir
            body = event if isinstance(event, dict) else {}

        http_method = event.get('httpMethod') or body.get('httpMethod') or 'POST'
        if http_method == 'OPTIONS':
            return create_response(200, {'message': 'CORS preflight successful'}, headers)

        if http_method != 'POST':
            return create_response(405, {'error': 'Method not allowed'}, headers)

        action = body.get('action')
        if action == 'upload_file':
            return handle_file_upload(body, headers)
        elif action == 'scan_file':
            return handle_file_scan(body, headers)
        elif action == 'get_scan_status':
            return get_scan_status(body, headers)
        elif action == 'download_report':
            return generate_simple_report(body, headers)
        else:
            return create_response(400, {'error': 'Geçersiz action parametresi'}, headers)

    except Exception as e:
        print("Lambda handler error:", repr(e))
        return create_response(500, {'error': f'İç sunucu hatası: {str(e)}'}, headers)


def handle_file_upload(body, cors_headers):
    """
    Upload: base64 file_content bekler, S3'e kaydeder ve DynamoDB'ye kayıt atar.
    """
    try:
        file_content = body.get('file_content')
        file_name = body.get('file_name')
        file_size = body.get('file_size')

        # required check
        if not file_name:
            return create_response(400, {'error': 'file_name gerekli'}, cors_headers)
        if file_content is None:
            return create_response(400, {'error': 'file_content (base64) gerekli'}, cors_headers)
        if file_size is None:
            return create_response(400, {'error': 'file_size gerekli'}, cors_headers)

        # ensure numeric
        try:
            file_size = int(file_size)
        except Exception:
            return create_response(400, {'error': 'file_size numeric olmalı'}, cors_headers)

        # size limit: 32MB
        if file_size > 32 * 1024 * 1024:
            return create_response(400, {'error': "Dosya boyutu 32MB'dan büyük olamaz"}, cors_headers)

        # decode base64 safely
        if isinstance(file_content, str):
            try:
                file_bytes = base64.b64decode(file_content)
            except Exception as e:
                print("base64 decode hata:", repr(e))
                return create_response(400, {'error': 'file_content base64 string olmalı'}, cors_headers)
        elif isinstance(file_content, (bytes, bytearray)):
            file_bytes = bytes(file_content)
        else:
            return create_response(400, {'error': 'file_content uygun formatta değil (string/bytes bekleniyor)'}, cors_headers)

        # optional: gerçek byte uzunluğunu doğrula (isteğe bağlı, frontend ile uyumlu değilse kaldırabilirsin)
        if len(file_bytes) != file_size:
            print(f"Uyarı: gelen file_size ({file_size}) ile gerçek bayt uzunluğu ({len(file_bytes)}) uyuşmuyor. Frontend doğrula.")

        # hash
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        s3_key = f"uploads/{file_hash}/{file_name}"

        # upload to S3
        s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=file_bytes, ContentType='application/octet-stream')
        now = datetime.utcnow().isoformat()
        scan_id = f"scan_{int(time.time())}_{file_hash[:8]}"

        # DynamoDB put
        table = dynamodb.Table(DYNAMODB_TABLE)
        table.put_item(Item={
            'scan_id': scan_id,
            'file_name': file_name,
            'file_size': file_size,
            'file_hash': file_hash,
            's3_key': s3_key,
            'status': 'uploaded',
            'created_at': now,
            'updated_at': now
        })

        return create_response(200, {'scan_id': scan_id, 'file_hash': file_hash, 'message': 'Dosya başarıyla yüklendi'}, cors_headers)

    except Exception as e:
        print("File upload error:", repr(e))
        return create_response(500, {'error': f'Dosya yükleme hatası: {str(e)}'}, cors_headers)


def handle_file_scan(body, cors_headers):
    """
    Başlatma: DynamoDB'den scan kaydını alır, VirusTotal'da var mı kontrol eder, yoksa dosyayı gönderir.
    """
    try:
        scan_id = body.get('scan_id')
        if not scan_id:
            return create_response(400, {'error': 'Scan ID gerekli'}, cors_headers)

        table = dynamodb.Table(DYNAMODB_TABLE)
        resp = table.get_item(Key={'scan_id': scan_id})
        if 'Item' not in resp:
            return create_response(404, {'error': 'Scan bulunamadı'}, cors_headers)

        item = resp['Item']
        file_hash = item.get('file_hash')
        if not file_hash:
            return create_response(500, {'error': 'Scan kaydında file_hash yok'}, cors_headers)

        # VirusTotal rapor kontrolü (file/report ile)
        vt_resp = make_http_get(f"{VIRUSTOTAL_API_URL}/file/report", params={'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash})
        if vt_resp and vt_resp.get('response_code') == 1:
            # hazır sonuç varsa işleme al
            return process_vt_results(scan_id, vt_resp, cors_headers)
        else:
            # yoksa submit et
            return submit_file_for_analysis(scan_id, file_hash, cors_headers)

    except Exception as e:
        print("File scan error:", repr(e))
        return create_response(500, {'error': f'Dosya analiz hatası: {str(e)}'}, cors_headers)


def submit_file_for_analysis(scan_id, file_hash, cors_headers):
    """
    S3'ten dosyayı alıp VirusTotal'a gönderir (requests kullanır).
    """
    try:
        # get item
        table = dynamodb.Table(DYNAMODB_TABLE)
        resp = table.get_item(Key={'scan_id': scan_id})
        if 'Item' not in resp:
            return create_response(404, {'error': 'Scan bulunamadı (submit)'}, cors_headers)
        item = resp['Item']
        s3_key = item.get('s3_key')
        file_name = item.get('file_name') or file_hash

        if not s3_key:
            return create_response(500, {'error': 'S3 key bulunamadı'}, cors_headers)

        s3_obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
        file_content = s3_obj['Body'].read()

        if requests is None:
            print("requests yok — multipart upload için requests ekleyin.")
            return create_response(500, {'error': 'requests kütüphanesi Lambda ortamında yok. Layer veya paket ekleyin.'}, cors_headers)

        vt_url = f"{VIRUSTOTAL_API_URL}/file/scan"
        files = {'file': (file_name, file_content)}
        data = {'apikey': VIRUSTOTAL_API_KEY}

        r = requests.post(vt_url, files=files, data=data, timeout=60)
        r.raise_for_status()
        vt_data = r.json()

        # DynamoDB update: scanning durumu
        table.update_item(
            Key={'scan_id': scan_id},
            UpdateExpression='SET #status = :status, #vt_scan_id = :vt_scan_id, #updated_at = :updated_at',
            ExpressionAttributeNames={'#status': 'status', '#vt_scan_id': 'vt_scan_id', '#updated_at': 'updated_at'},
            ExpressionAttributeValues={':status': 'scanning', ':vt_scan_id': vt_data.get('scan_id'), ':updated_at': datetime.utcnow().isoformat()}
        )

        return create_response(200, {'scan_id': scan_id, 'status': 'scanning', 'message': 'Dosya analiz için gönderildi'}, cors_headers)

    except Exception as e:
        print("Submit file error:", repr(e))
        return create_response(500, {'error': f'Dosya gönderim hatası: {str(e)}'}, cors_headers)


def make_http_get(url, params=None):
    """
    Basit GET yardımcı: requests varsa kullanır, yoksa urllib ile basit GET yapar.
    """
    try:
        if requests:
            r = requests.get(url, params=params, timeout=20, headers={'User-Agent': 'VT-Scanner/1.0'})
            r.raise_for_status()
            return r.json()
        else:
            # fallback: urllib
            import urllib.request, urllib.parse
            qs = urllib.parse.urlencode(params or {})
            full = f"{url}?{qs}" if qs else url
            req = urllib.request.Request(full, headers={'User-Agent': 'VT-Scanner/1.0'})
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode())
    except Exception as e:
        print("HTTP request error:", repr(e))
        return None


def process_vt_results(scan_id, vt_data, cors_headers):
    """
    VT sonuçlarını işler, DynamoDB'ye kaydeder ve son durumu döner.
    """
    try:
        scans = vt_data.get('scans') or {}
        total_scanners = len(scans)
        malicious_count = sum(1 for s in scans.values() if s.get('detected'))
        clean_count = total_scanners - malicious_count
        detection_rate = (malicious_count / total_scanners * 100) if total_scanners > 0 else 0.0

        table = dynamodb.Table(DYNAMODB_TABLE)
        table.update_item(
    Key={'scan_id': scan_id},
    UpdateExpression='SET #status = :status, #vt_results = :vt_results, #stats = :stats, #updated_at = :updated_at',
    ExpressionAttributeNames={
        '#status': 'status',
        '#vt_results': 'vt_results',
        '#stats': 'stats',
        '#updated_at': 'updated_at'
    },
    ExpressionAttributeValues={
        ':status': 'completed',
        ':vt_results': vt_data,
        ':stats': {
            'total_scanners': total_scanners,
            'malicious_count': malicious_count,
            'clean_count': clean_count,
            'detection_rate': Decimal(str(round(detection_rate, 2)))  
        },
        ':updated_at': datetime.utcnow().isoformat()
    }
)
        return create_response(200, {
            'scan_id': scan_id,
            'status': 'completed',
            'stats': {
                'total_scanners': total_scanners,
                'malicious_count': malicious_count,
                'clean_count': clean_count,
                'detection_rate': round(detection_rate, 2)
            },
            'message': 'Analiz tamamlandı'
        }, cors_headers)

    except Exception as e:
        print("Process VT results error:", repr(e))
        return create_response(500, {'error': f'Sonuç işleme hatası: {str(e)}'}, cors_headers)


def get_scan_status(body, cors_headers):
    """
    Scan durumunu döner; eğer 'scanning' ise VirusTotal'dan poll yapar.
    """
    try:
        scan_id = body.get('scan_id')
        if not scan_id:
            return create_response(400, {'error': 'Scan ID gerekli'}, cors_headers)

        table = dynamodb.Table(DYNAMODB_TABLE)
        resp = table.get_item(Key={'scan_id': scan_id})
        if 'Item' not in resp:
            return create_response(404, {'error': 'Scan bulunamadı'}, cors_headers)

        item = resp['Item']
        if item.get('status') == 'scanning' and item.get('file_hash'):
            vt_response = make_http_get(f"{VIRUSTOTAL_API_URL}/file/report", params={'apikey': VIRUSTOTAL_API_KEY, 'resource': item['file_hash']})
            if vt_response and vt_response.get('response_code') == 1:
                return process_vt_results(scan_id, vt_response, cors_headers)

        return create_response(200, {
            'scan_id': scan_id,
            'status': item.get('status'),
            'file_name': item.get('file_name'),
            'created_at': item.get('created_at'),
            'stats': item.get('stats'),
            'vt_results': item.get('vt_results')
        }, cors_headers)

    except Exception as e:
        print("Get scan status error:", repr(e))
        return create_response(500, {'error': f'Durum kontrol hatası: {str(e)}'}, cors_headers)

def generate_simple_report(body, cors_headers):
    """
    Basit JSON rapor oluşturur ve S3'e kaydeder; presigned URL döner.
    """
    try:
        scan_id = body.get('scan_id')
        if not scan_id:
            return create_response(400, {'error': 'Scan ID gerekli'}, cors_headers)

        table = dynamodb.Table(DYNAMODB_TABLE)
        resp = table.get_item(Key={'scan_id': scan_id})
        if 'Item' not in resp:
            return create_response(404, {'error': 'Scan bulunamadı'}, cors_headers)

        item = resp['Item']
        if item.get('status') != 'completed':
            return create_response(400, {'error': 'Analiz henüz tamamlanmadı'}, cors_headers)

        report_data = {
            'scan_id': scan_id,
            'file_name': item.get('file_name'),
            'file_size': item.get('file_size'),
            'file_hash': item.get('file_hash'),
            'scan_date': item.get('created_at'),
            'status': item.get('status'),
            'stats': item.get('stats'),
            'vt_results': item.get('vt_results')
        }

        report_key = f"reports/{scan_id}/report.json"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=report_key,
            Body=json.dumps(report_data, ensure_ascii=False, indent=2, cls=DecimalEncoder),  # DecimalEncoder eklendi
            ContentType='application/json'
        )

        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': S3_BUCKET, 'Key': report_key},
            ExpiresIn=86400
        )
        return create_response(200, {'scan_id': scan_id, 'report_url': presigned_url, 'report_type': 'json', 'message': 'JSON rapor oluşturuldu'}, cors_headers)

    except Exception as e:
        print("Generate report error:", repr(e))
        return create_response(500, {'error': f'Rapor oluşturma hatası: {str(e)}'}, cors_headers)


def create_response(status_code, body, cors_headers):
    return {
        'statusCode': status_code,
        'headers': cors_headers,
        'body': json.dumps(body, ensure_ascii=False, cls=DecimalEncoder)  
    }
```
     
   
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

## Katkı

Bu proje, kurumsal güvenlik analizi ve dosya tarama çözümleri geliştirmek isteyen geliştiriciler için örnek teşkil etmektedir.

---

