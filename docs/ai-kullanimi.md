# AI Kullanımı — Şeffaflık Açıklaması

Sentinel-Agent'ta yapay zekâ **iki ayrı yerde** kullanılır. İkisini bilinçli olarak ayırıyoruz;
çünkü projenin temel güvenlik iddiası buna dayanır: **LLM akıl yürütür, deterministik motor kanıtlar.**

---

## 1. Yapım sürecinde (build-time) — Claude Code

Kod tabanı, **Claude Code** (Anthropic'in CLI ajanı) ile eşli-programlama yaklaşımıyla geliştirildi.
AI'ın yapım sürecindeki rolü:

- OOP + modüler iskeletin (models → policy → net → oracle → auth → evidence → report → scanner)
  kurulması ve `ABC` tabanlı genişletme noktalarının (Oracle/AuthProvider/Reporter alt sınıfları) yazımı.
- Network'süz birim testlerin (`httpx.MockTransport`) ve kenar-durum senaryolarının üretilmesi.
- Belge (DESIGN.md, README) ve statik HTML rapor görüntüleyicisinin hazırlanması.

Tüm AI-üretimi kod insan tarafından gözden geçirildi; mimari kararlar, güvenlik değişmezleri ve
kabul kriterleri ekibe aittir. AI bir hızlandırıcıdır, karar mercii değildir.

## 2. Çalışma zamanında (runtime) — Gemini / Ollama (ve opsiyonel Anthropic)

Tarama sırasında bir LLM sağlayıcısı (**Google Gemini** bulut API'si veya **Ollama** ile yerel
açık model; opsiyonel olarak Anthropic) **yardımcı akıl yürütme** için devreye girer:

- **Hipotez üretimi:** endpoint envanterinden hangi zafiyet tiplerinin (IDOR/BFLA/aşırı-veri/injection)
  denenmeye değer olduğunu önerir (`ProposeHypothesis` — tipli aksiyon).
- **Bulgu zenginleştirme:** doğrulanmış bulgulara severity/impact/remediation açıklaması ekler.
- **INCONCLUSIVE triyaj:** belirsiz sonuçlara insan-okur yorum yazar.

### Değişmez sınırlar (LLM'in yapamadıkları)

Bu, aracın en kritik tasarım kararıdır ve runtime AI'ı güvenli kılan şeydir:

1. **LLM ağa asla dokunmaz.** Yalnızca tipli aksiyon önerir; tüm trafik deterministik `Replayer`'dan geçer.
2. **`CONFIRMED` kararını her zaman kod verir, asla LLM.** Kanıt yalnızca deterministik leaked-marker
   (kurbanın özel verisinin saldırganın cevabında görünmesi) ile üretilir.
3. **Kontroller (positive/negative/stability) geçmeden verdict yoktur** — LLM bunu atlayamaz.
4. **Scope kapısı her istekte zorlanır** (`PolicyEngine.authorize`); LLM önerisine güvenilmez.

Kısaca: LLM "neyi deneyelim ve sonuç ne anlama geliyor" sorusunu yanıtlar; "gerçekten açık var mı"
sorusunu **kod** yanıtlar. LLM tamamen devre dışı bırakılsa (`--llm none`) araç yine deterministik
olarak çalışır ve kanıtlı bulgu üretir — AI yalnızca kapsama ve açıklama kalitesini artırır.
