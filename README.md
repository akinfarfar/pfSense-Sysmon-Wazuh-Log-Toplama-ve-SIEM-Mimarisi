# pfSense-Sysmon-Wazuh-Log-Toplama-ve-SIEM-Mimarisi
Bu proje, farklı işletim sistemlerinden gelen logların pfSense ile yönetilen izole bir ağ üzerinde toplanarak Wazuh SIEM platformunda analiz edilmesini amaçlayan uçtan uca bir güvenlik mimarisidir.

<img width="213" height="183" alt="image" src="https://github.com/user-attachments/assets/575b8634-24d0-497a-b668-bfb7e1dfe4df" />


🎯 **Proje Amaçları**

Gerçek bir SOC ortamında kullanılan log akışını simüle etmek
Sysmon ile gelişmiş Windows event logları toplamak
Ubuntu üzerinden Linux tabanlı logları Wazuh’a aktarmak
pfSense ile ağ segmentasyonu ve güvenli trafik yönetimi yapmak
SIEM üzerinde korelasyon, alerting ve temel tehdit avcılığı pratiği kazanmak

| Bileşen                 | Açıklama                                  |
| ----------------------- | ----------------------------------------- |
| **pfSense**             | Ağ segmentasyonu, Firewall / NAT yönetimi |
| **Sysmon**              | Windows davranışsal olay kayıt sistemi    |
| **Wazuh SIEM**          | Log toplama, analiz, MITRE ATT&CK eşleme  |
| **Windows 10/11**       | Sysmon agent testleri                     |
| **Ubuntu 22.04**        | Linux log agent                           |
| **VirtualBox / VMware** | Sanal ortam altyapısı                     |

⚙️ **Kurulum Adımları**

1️⃣ 🌐 **pfSense Kurulumu ve Ağ Sertleştirmesi**

Bu projede, güvenli ve yönetilebilir bir izleme ortamı oluşturmak amacıyla ağ katmanını pfSense ile yönettim ve sertleştirdim. pfSense kullanımı, sadece temel yönlendirmenin ötesinde, ağ trafiği kontrolü ve güvenlik politikaları oluşturma yetkinliğimi göstermektedir.

**1. DHCP Sabit Atamaları (DHCP Reservation)**
SIEM ortamlarında tutarlılık (consistency) esastır. Wazuh Agent'ların Manager ile güvenilir bir şekilde iletişim kurabilmesi ve log verilerinde Agent kimliklerinin sürekli aynı IP adresiyle ilişkilendirilmesi için DHCP Sabit Atamaları kullandım.

| Makine | IP Adresi |
|--------|-----------|
| Wazuh Manager (Ubuntu) | 192.168.1.100 |
| Windows Agent | 192.168.1.101 |
| Ubuntu Agent | 192.168.1.102 |

<img width="370" height="170" alt="image" src="https://github.com/user-attachments/assets/684a1deb-b2aa-406d-8315-bfc23abe0b4b" />


*LAN üzerindeki istemcilere statik IP atanmadığı durumlarda, istemcinin IP adresi değişirse Wazuh Agent bağlantısı kopabilir. Bu durumda /var/ossec/etc/ossec.conf dosyasındaki server IP adresini güncel ağ yapısına göre düzenlediğinizde agent, Wazuh Server’a yeniden bağlanacaktır.Bu durum, özellikle pfSense DHCP Sabit Atamaları yapılmadığı takdirde karşılaşılabilecek bağlantı kopukluklarının (Agent Disconnected durumu) önüne geçmek için kritik öneme sahiptir.

<img width="645" height="461" alt="conf" src="https://github.com/user-attachments/assets/4284f159-2cf3-40f3-a4fc-f0b7839ae010" />

Amaç: Wazuh Manager (Ubuntu) ve Windows/Ubuntu Agent makinelerinin IP adreslerinin ağda sabit kalmasını sağlamak.

Uygulama: Her Agent ve Manager sunucusu için, MAC adreslerini kullanarak pfSense DHCP sunucusu üzerinde kalıcı IP adresleri (192.168.1.100, vb.) tanımladım. Bu, makinelerin IP'yi dinamik olarak alsalar bile, her zaman aynı sabit IP'ye sahip olmasını garanti etti. Bu yöntem, Agent'ların yeniden başlatılması durumunda bile SIEM loglarında veri tutarsızlığını önledi.

**2. Güvenlik Duvarı Kuralları (Firewall Rules)**

Ağ katmanında en az ayrıcalık (Least Privilege) prensibini uygulayarak, sadece zorunlu trafiğe izin veren katı kurallar oluşturdum.

Amaç: LAN trafiğini kontrol etmek, Manager'ın kritik portlarını korumak ve Agent-Manager iletişiminin güvenliğini sağlamak.

Uygulama: pfSense LAN Arayüzü üzerinde aşağıdaki kritik kuralları uyguladım:

| **Kural**                           | **Protokol / Port** | **Kaynak / Hedef**                         | **Açıklama**                                                                                                                                                                      |
| ----------------------------------- | ------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Kural 1 (Wazuh Agent İletişimi)** | TCP / 1514          | LAN Ağları → Wazuh Manager (192.168.1.100) | Wazuh Agent'ların Manager'a log ve durum verisi göndermesi için gerekli olan portu güvenli şekilde açtım.                                                                         |
| **Kural 2 (DNS/HTTP Çıkışı)**       | TCP/UDP / 53 (DNS)  | LAN Ağları → Any                           | Agent'ların ve diğer makinelerin güncellemeleri alabilmesi ve isim çözümlemesi yapabilmesi için temel internet erişimine izin verdim.                                             |
| **Son Kural (Engelleme)**           | Her Şey             | Any → Any                                  | Bu kuralların dışında kalan tüm kontrolsüz LAN trafiğini engelledim. Bu, ağda yetkisiz port taramalarını ve potansiyel yanal hareketleri önleyen temel bir sertleştirme adımıdır. |

Bu yapılandırma, Agent-Manager arasındaki iletişimin güvenliğini sağlarken, aynı zamanda ağımın genel güvenlik duruşunu yükseltmiştir.

<img width="789" height="258" alt="image" src="https://github.com/user-attachments/assets/f47cfbe0-33c1-4a6d-9290-4c7e74bbd25d" />



**2️⃣ 🛡️ Wazuh Server Kurulumu ve Hazırlık**
Bu aşamada, tüm logların toplandığı, analiz edildiği ve uyarıların üretildiği merkezi SIEM platformu olan Wazuh Manager ve kullanıcı arayüzü olan Wazuh Dashboard'u kurdum ve operasyonel hale getirdim. Kurulumlar, Wazuh'un resmi belgeleri takip edilerek Ubuntu Server üzerinde gerçekleştirildi.

*2.1. Wazuh Manager ve Dashboard Kurulumu*

Wazuh, üç ana bileşenden oluşur: Wazuh Indexer (veri depolama), Wazuh Manager (analiz ve kural motoru) ve Wazuh Dashboard (arayüz).

Amaç ve Açıklama: Sistemdeki tüm logları ve uyarıları merkezi olarak işleyip depolamak için bu üç bileşeni tek bir Ubuntu sunucusu üzerinde (All-in-One kurulum) kurdum. Kurulumu takiben, Manager'ın tüm Agent'lardan log alabilmesi için temel konfigürasyonlarını (özellikle ağ bağlantılarını) doğrulanmıştır.

Gösterilen Yetkinlik: Linux Sunucu Yönetimi, Üç Katmanlı Mimari (Three-Tier Architecture) Kurulumu, Dağıtık Sistem Yönetimi.

<img width="1413" height="432" alt="image" src="https://github.com/user-attachments/assets/ac2df428-bbe7-4769-a612-bf00d5741074" />

<img width="1250" height="198" alt="image" src="https://github.com/user-attachments/assets/651e5623-0676-4c68-bb57-92b824195f87" />

<img width="1094" height="199" alt="image" src="https://github.com/user-attachments/assets/85dd4b3d-f565-476b-8ca2-f74812cf64e1" />



*2.2. API Bağlantı Testleri*

Amaç ve Açıklama: Wazuh Dashboard'un Manager ile doğru şekilde iletişim kurabilmesi ve Agent yönetim fonksiyonlarının çalışması için Wazuh API'sinin (55000/TCP) sağlıklı çalışıp çalışmadığını test ettim. Manager sunucusunda *curl* komutu ile kimlik doğrulama yaparak başarılı bir JSON yanıtı aldım. Bu, API servisinin dinlediğini ve kimlik doğrulama (Indexer kullanıcıları) mekanizmasının düzgün çalıştığını kanıtlar.

Gösterilen Yetkinlik: API Servis Yönetimi, Sertifika Doğrulama, Ağ Servis Kontrolü.

<img width="1255" height="73" alt="image" src="https://github.com/user-attachments/assets/d6ae1ecb-afb7-4921-9979-4b02125d3a66" />

<img width="1407" height="419" alt="image" src="https://github.com/user-attachments/assets/fe997c81-acea-4fcd-a2ff-77900416f34b" />


*2.3. Agent Enrollment İzinlerinin Açılması (Güvenlik Duvarı Yönetimi)*

Güvenlik duruşunu korumak ve aynı zamanda Agent iletişimini sağlamak için, Ubuntu Manager üzerinde UFW (Uncomplicated Firewall) üzerinden yalnızca gerekli portlara izin verdim.

Uygulanan UFW Kuralları:

1514/TCP: Agent'lardan gelen log verisi akışına izin.

1515/TCP: Yeni Agent'ların Manager'a kayıt olmasına (enrollment) izin.

9200/TCP (veya 9200-9300): Indexer/Cluster iletişimi ve Dashboard erişimine izin.

Bu sayede, pfSense'te açılan kurala ek olarak Manager'ın kendisinde de bu portlar izole edilmiş oldu.

<img width="1256" height="70" alt="image" src="https://github.com/user-attachments/assets/8c7867cf-a44f-4c78-a064-ad92bb800485" />




**3️⃣ Windows Sysmon Entegrasyonu ve Derin Uç Nokta Görünürlüğü**

Projemin kilit noktası, standart Windows olay günlüklerinin ötesine geçerek uç nokta seviyesinde derinlemesine güvenlik görünürlüğü sağlamaktır. Bu amaçla, Windows Server 2022 Agent makinesine Microsoft Sysmon (System Monitor) uygulamasını entegre ettim.

*3.1. Sysmon Kurulumu ve Konfigürasyonu*

Sysmon, çekirdek düzeyinde aktiviteyi izleyen ve bu verileri Windows olay günlüklerine yazan bir Windows sistem hizmetidir.
*Kurulum: Sysmon'ı Windows Server'a indirdim ve hizmet olarak kurdum.

https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

*Konfigürasyon: Sysmon, kurulumdan sonra izleyeceği olayları tanımlayan bir konfigürasyon dosyasına ihtiyaç duyar. Kapsamlı ve gürültüden arındırılmış izleme sağlamak için, genellikle SwiftOnSecurity veya benzeri, sektörde kabul görmüş bir XML konfigürasyon dosyası kullandım. Bu konfigürasyon, bilinen iyi aktiviteleri filtrelerken (whitelist), potansiyel olarak kötü amaçlı veya anormallik içeren olayları yakalamaya odaklanır.

https://github.com/SwiftOnSecurity/sysmon-config

<img width="973" height="159" alt="image" src="https://github.com/user-attachments/assets/ee04f8e4-678f-4cd2-a853-66a50a120925" />

*3.2. Wazuh Tarafında Sysmon Loglarının İşlenmesi*

Sysmon loglarının anlamlı uyarılara dönüşebilmesi için, Wazuh Manager'ın bu olayları doğru bir şekilde alıp işleyebilmesi gerekir.

*Log Toplama: Wazuh Agent, Sysmon'ın yazdığı olay günlüklerini (genellikle Microsoft-Windows-Sysmon/Operational yolu altında bulunur) otomatik olarak toplar.

*Wazuh'un Varsayılan Kuralları: Wazuh, Sysmon olayları için özel olarak tasarlanmış geniş bir kural setine sahiptir. Bu kurallar, Manager'ın kural setinde varsayılan olarak etkinleştirilmiştir. Bu sayede, Agent'tan gelen Sysmon olayları, Manager'daki bu kurallarla eşleştirilir ve otomatik olarak güvenlik uyarılarına (Alerts) dönüştürülür.

*Değer: Bu entegrasyon, saldırganların kullanabileceği Living off the Land (LotL) teknikleri, şüpheli PowerShell yürütmeleri ve yetkisiz ağ bağlantıları gibi kritik olayların hızlıca tespit edilmesini sağladı.

3.3. Odaklanılan Kritik Sysmon Event ID'leriOdaklandığım ve SIEM açısından en yüksek değere sahip olan temel Sysmon olay kimlikleri (Event ID'ler) şunlardır:

| **Event ID** | **Adı**                                                         | **Önemi**                                                                                                                                                                 |
| ------------ | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1**        | Process Creation (Süreç Oluşturma)                              | Bir sistemde başlatılan her yeni süreci izler. Anormal yürütülebilir dosyaların (EXE, DLL) veya bilinen zararlı süreçlerin tespitinde kritik rol oynar.                   |
| **3**        | Network Connection (Ağ Bağlantısı)                              | Bir sürecin hangi IP adresi ve port üzerinden dışarıyla bağlantı kurduğunu gösterir. Komuta Kontrol (C2) trafiği ve veri sızdırma girişimlerinin izlenmesi için temeldir. |
| **5**        | Process Terminated (Süreç Sonlandırma)                          | Bir sürecin sonlandırılmasını kaydeder. Potansiyel olarak kötü amaçlı süreçlerin zorla kapatılmasını izlemeye yardımcı olur.                                              |
| **11**       | File Creation Time Changed (Dosya Oluşturma Zamanı Değişikliği) | Timestomp (zaman damgası manipülasyonu) gibi adli analizden kaçınma tekniklerini tespit etmek için kullanılır.                                                            |


Bu Event ID'lere odaklanmak, zararlı yazılım yürütme zincirini, yanal hareketleri ve veri sızdırma adımlarını gerçek zamanlı olarak izleme yeteneğimi kanıtladı. Proje, uç nokta güvenliğinde proaktif izleme ve tehdit avcılığı (Threat Hunting) yeteneklerimi önemli ölçüde artırmıştır.

**4️⃣Ubuntu Agent Kurulumu ve Linux Log Entegrasyonu**

Bu aşamada, izole ağdaki Ubuntu sunucuyu, Wazuh Agent aracılığıyla Manager'a bağladım. Bu, Windows uç noktadan farklı olarak, Linux işletim sisteminin çekirdek günlüklerini ve kritik servis kayıtlarını merkezi olarak izlememi sağladı.

*4.1. Agent Kurulumu ve Kayıt İşlemi (Enrollment)*

Amaç ve Açıklama: Ubuntu Agent'ın kurulumunu gerçekleştirdim ve Agent'ı Manager'ın IP adresi (192.168.1.100) üzerinden kaydettim (enrollment). Agent, Manager'a kaydolurken benzersiz bir şifreleme anahtarı (key) alır ve bu anahtarı gelecekteki güvenli iletişimler için kullanır.

Uygulama: Kurulumu otomatikleştirmek için tek satırlık komut satırı yöntemini tercih ettim. Bu komut, Agent paketini indirir, Manager IP'sini ayarlar ve Agent servisini başlatır.

# Kurulum betiği örneği (Ubuntu 22.04 için)
sudo WAZUH_MANAGER='192.168.1.100' apt install ./wazuh-agent-4.x.x.deb
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

Gösterilen Yetkinlik: Linux Paket Yönetimi (apt), Servis Yönetimi (systemctl), Agent Dağıtımı.

*4.2. Kritik Linux Loglarının Toplanması*
Wazuh, kurulumla birlikte standart Linux loglarını otomatik olarak okumak için yapılandırılır. Bu, güvenlik analizi için kritik öneme sahiptir.

Amaç ve Açıklama: Ubuntu Agent'ın Manager'a gönderdiği temel log türlerini doğruladım. Bu loglar, Wazuh Manager tarafından analiz edilerek, Linux sistemine özel tehditlere karşı uyarılar üretir. Odaklandığım başlıca loglar şunlardır:

**/var/log/auth.log**: Kullanıcı kimlik doğrulama, sudo kullanımı ve SSH bağlantıları gibi yetkilendirme olaylarını içerir.

**/var/log/syslog**: Sistemin genel durumu, kernel ve diğer servislerin mesajlarını içerir.

**/var/log/dpkg.log**: Sistemdeki paket kurulum/kaldırma işlemlerini kaydeder (yazılım bütünlüğünü izleme).

Kontrol: Agent'ın log gönderip göndermediğini teyit etmek için Manager Dashboard'da Agent'ın durumunu kontrol ettim ve loglarda bu dosyalardan gelen girişleri filtreledim.

*4.3. Agent Sağlık Kontrolleri (Agent Health Checks)*
Agent'ın sürekli olarak Manager ile iletişimde kalması, SIEM güvenilirliği için zorunludur.

Amaç ve Açıklama: Agent'ın doğru IP adresine bağlandığını ve aktif olduğunu sürekli kontrol ettim. Özellikle pfSense'te IP ataması yapıldığı için bağlantının kopmaması gerekiyordu.

Agent Logları: Agent makinesinde /var/ossec/logs/ossec.log dosyasını kontrol ederek bağlantı hatalarını veya başarılı Manager bağlantılarını doğruladım.

Manager Dashboard: Dashboard üzerinde Ubuntu Agent'ın durumunu sürekli olarak Active (Aktif) olarak gözlemledim.

Gösterilen Yetkinlik: Agent İzleme ve Sorun Giderme (Troubleshooting), Sürekli Çalışırlık (Availability) Yönetimi.

<img width="914" height="172" alt="image" src="https://github.com/user-attachments/assets/8046af99-43fd-468d-be11-6ad7ecc37a46" />

<img width="1394" height="21" alt="image" src="https://github.com/user-attachments/assets/6027c917-dc8c-4eb7-a970-8753df08ae8c" />



**5️⃣Wazuh Dashboard İncelemeleri (Analiz ve Korelasyon)**

Bu bölümde, kurulan altyapının ürettiği veriyi nasıl işlediğimi, uluslararası güvenlik standartlarına göre nasıl değerlendirdiğimi ve olası tehditleri nasıl analiz ettiğimi gösteriyorum.

*5.1. Güvenlik Olayları (Security Events) İncelemesi*

Bu, SIEM'in kalbidir ve gerçek zamanlı tehdit tespitini kanıtlar.

*Amaç ve Açıklama: Wazuh'un kural motoru tarafından işlenmiş, önceliklendirilmiş ve korelasyonu yapılmış uyarıları inceledim. Yüksek öncelikli (Level 10 ve üzeri) uyarıları filtreleyerek acil müdahale gerektiren olaylara odaklandım. Bu, Windows Server üzerindeki yetkisiz oturum açma girişimleri (Event ID 4625) veya Ubuntu üzerinde root erişim denemeleri gibi kritik olayları kapsamaktadır.

*Gösterilen Yetkinlik: Olay Önceliklendirme, Gerçek Zamanlı İzleme, Kural Mantığını Anlama.

<img width="1052" height="806" alt="image" src="https://github.com/user-attachments/assets/1e828fbc-2661-4af9-b3ff-41fd1ddb7558" />

*5.2. MITRE ATT&CK Modülü*

Modern güvenlik analistleri için tehditleri basit bir ID numarası yerine global bir çerçeveye oturtmak kritik öneme sahiptir.

Amaç ve Açıklama: Wazuh'un yerleşik MITRE ATT&CK modülünü kullanarak, Manager tarafından üretilen uyarıların hangi Taktik (Tactic) ve Teknik (Technique) ile eşleştiğini analiz ettim. Örneğin, bir zararlı sürecin başlatılması Sysmon tarafından tespit edildiğinde, bu olayın MITRE ATT&CK matrisinde Yürütme (Execution - Tactic) altında Komut ve Betik Yorumlayıcı (T1059) tekniğine nasıl bağlandığını gördüm.

Gösterilen Yetkinlik: Tehdit İstihbaratını Uygulama, Saldırgan Yaşam Döngüsünü Anlama, Stratejik Savunma Planlaması.

<img width="1409" height="856" alt="image" src="https://github.com/user-attachments/assets/ac9d20dc-8700-4f13-8448-9825476af1c7" />


*5.3. PCI-DSS / CIS Benchmark Modülleri (SCA)*

Bu bölüm, uyumluluk (compliance) ve yapılandırma değerlendirmesi (Configuration Assessment) bilginizi kanıtlar.

Amaç ve Açıklama: Wazuh'un Sistem Yapılandırma Analizi (System Configuration Assessment - SCA) özelliğini kullanarak Agent'lar üzerindeki işletim sistemlerinin (Windows ve Ubuntu) güvenlik standartlarına uygunluğunu otomatik olarak değerlendirdim. Özellikle CIS Benchmarks (Center for Internet Security) ve gerekirse PCI-DSS kontrollerine göre sistemlerin mevcut skorlarını ve uyumsuzluklarını (fail) gözlemledim. Bu, sistemlerin güvenlik açısından sertleştirilip sertleştirilmediğini sürekli izlememi sağladı.

Gösterilen Yetkinlik: Uyumluluk İzleme, Yapılandırma Sertleştirme (Hardening), Güvenlik Denetimi.

<img width="1410" height="851" alt="image" src="https://github.com/user-attachments/assets/11fabf99-096a-448f-909b-4abfc2b305f9" />

*5.4. Sysmon Log İncelemeleri (Tehdit Avcılığı)*

Burası, Sysmon'ın getirdiği derinliği ve basit uyarılardan öte, Tehdit Avcılığı (Threat Hunting) yapabildiğinizi gösterir.

Amaç ve Açıklama: Ham logları incelemek için Discover modülünü kullandım. Özellikle Sysmon'dan gelen verileri filtreleyerek, Wazuh tarafından henüz uyarıya dönüşmemiş ancak şüpheli olabilecek düşük seviyeli olayları aradım. Örneğin, bir sürecin hangi dış IP'ye bağlandığını görmek için Sysmon Event ID 3 (Network Connection) loglarını doğrudan inceleyerek uç nokta bağlantılarını haritaladım.

Gösterilen Yetkinlik: Ham Veri Analizi, Tehdit Avcılığı, Derinlemesine Teknik İnceleme.

<img width="1412" height="772" alt="image" src="https://github.com/user-attachments/assets/456a22be-6e8c-4f83-8eec-c8eda6ed80e5" />

*5.5. Rule Set Testleri (wazuh-logtest)*
Bu, Wazuh'un kural motorunun işleyişini anladığınızı ve detection logic'i doğrulayabildiğinizi gösterir.

Amaç ve Açıklama: Özelleştirilmiş bir kural yazmadan önce veya mevcut kuralların beklediğim gibi çalıştığından emin olmak için Wazuh Manager sunucusunda wazuh-logtest aracını kullandım. Bu araç sayesinde, bir Agent'tan gelmesi beklenen örnek bir ham log satırını simüle ettim ve Wazuh'un bu logu hangi Rule ID ve Alarm Seviyesi (Level) ile işleyeceğini canlı olarak doğruladım.

Gösterilen Yetkinlik: Kural Geliştirme, Log İşleme Boru Hattı (Pipeline) Bilgisi, Sorun Giderme (Troubleshooting).

<img width="1410" height="418" alt="image" src="https://github.com/user-attachments/assets/3cc07935-78d6-4879-8795-12f5e5941b9c" />


📝 Sonuç
Bu proje, bir SOC ortamındaki temel bileşenleri barındıran, hem ağ hem endpoint hem de SIEM düzeyinde pratik kazandıran bir yapıdır.
Genişletilebilirliği sayesinde ileride:
*Malware testleri
*Olay senaryoları
*Özel Wazuh kural yazımı
*Log korelasyon çalışmaları gibi eklemeler yapılabilir.

<img width="1057" height="611" alt="image" src="https://github.com/user-attachments/assets/6640aec0-e502-417a-a9ad-a7f811e2ed97" />    <img width="1473" height="888" alt="image" src="https://github.com/user-attachments/assets/46e9c61b-835a-4968-9291-8ea26c3c547e" />

<img width="1477" height="889" alt="image" src="https://github.com/user-attachments/assets/d3a168c4-2cd3-4d09-b637-6344b15b58f5" />


