# IDEAS — رؤية vtknet غير المحدودة

> **[وثيقة رسمية معتمدة — خارطة الطريق التنفيذية للمشروع]** — اعتُمدت في
> 2026-11-11؛ تُحدَّث بعد كل sprint، والأفكار المنفذة تنتقل إلى `CHANGELOG.md`.
> صيغت بعد قراءة كاملة للكود + بحث خارجي (Dalton / JA5 / PQ-TLS / AEV / eBPF).
>
> **قواعد صريحة تحكم هذا الملف:**
> 1. **لا سقف للاداة** — كل فكرة قدرة أدناه in scope بالتعريف، مهما كانت طموحة.
> 2. **لا قيود مفروضة على المستخدم** — لا حراسة نطاق، لا بوابات إذن، لا
>    "حماية من المستخدم". الأداة حرة وطليقة، والفلتر الوحيد لأي فكرة هو:
>    هل تجعل الأداة أقدر وأكثر فرادة؟
>
> الهدف ليس نسخ nmap أو wireshark — بل امتلاك الحلقة الكاملة التي لا يمتلكها
> أي منهما.

---

## الأطروحة — أغلق الحلقة

معظم الأدوات تمتلك حلقة واحدة. نهاية الطريق أن تمتلكها كلها:

    ولّد الحقيقة → أرسل/التقط → أرفق الدليل → تذكّر → قارن عبر الزمن
    → استنتج واربط → أثبت (verify & sign) → تعلّم وتكيّف

**ثلاثية الفرادة** (التركبة التي لا يملكها أحد): Evidence بالبايتات +
ذاكرة زمنية + reproducibility مضمونة بالـ seed. nmap سريع لكنه صامت،
wireshark عميق لكن بلا ذاكرة، hping3 يصنع ولا يتذكر، tcpreplay يعيد ولا يولّد.
vtknet هو النسيج الضام — ثم الجسم كله.

---

## 1 — المحرك: بلا حدود صناعية

- **IPv6 مواطن من الدرجة الأولى** — `utils/net.expand_hosts` يرفض v6 صراحة
  اليوم؛ اقلبها: NDP discovery، ICMPv6 sweep، TCP/UDP scan6، ثم **رصد Rogue
  Router Advertisement** (النسخة v6 من rogue-DHCP/evil-twin). أقل طبقة تغطية
  في الشبكات الحديثة = أكبر فرصة فرادة.
- **UDP scan** — ICMP port-unreachable → `closed`، صمت → `open|filtered`،
  رد → `open`. يقع مباشرة على الـ Engine الحالي.
- **Async engine (asyncio)** — event loop واحد، آلاف المحادثات المتزامنة
  بعد حدود الـ thread pools (موجود في الـ roadmap).
- **Token-bucket pacing** — الـ pacing اليوم لكل batch (متقطع)؛ الـ bucket
  الحقيقي يعطي معدلاً ناعماً تماماً من 0.1 pps حتى سرعة السلك.
- **Adaptive rate** — عند رصد ICMP rate-limiting أو loss يتباطأ المحرك
  تلقائياً ويوثّق ذلك في الـ report.
- **Send-while-sniffing** — Capture في الخلفية + إرسال حر يلتقط الردود
  غير المتماثلة (ICMP unreachable، RST من أطراف ثالثة) التي يفوّتها
  ارتباط `sr()`.
- **Multi-host TCP scan** — `scan` لجهاز واحد اليوم (cli يرفض CIDR)؛ ارفع
  القيد ودع الـ Engine يجدول مصفوفة host×port أصلياً.
- **JSONL streaming** — فحص 65535 بورت × شبكة كاملة لا يحتمل البناء في
  الذاكرة؛ `Engine.send_recv` يعيد النتيجة دفعة واحدة اليوم.
- **Resume/checkpoint** — المسح الطويل يحفظ تقدمه؛ `--resume` يكمل بنفس
  الـ seeds.

## 2 — وحدات القياس (probes)

- **`banner`** — TCP connect + قراءة أول بايتات (HTTP Server, SSH, SMTP, FTP).
  أرخص وحدة وأعلى مردود؛ تكمل `tls`.
- **`traceroute`/`route`** — كل hop بدليل reply محفوظ + MPLS labels؛ بيانات
  TTL تُجمع أصلاً داخل findings الـ scanner.
- **`passive`** — صفر باكتس: استمع، استنتج hosts/OS/services من ضجيج
  ARP/DNS/mDNS، ثم *اقترح* الـ probes النشطة المهمة. "اسمع قبل أن تلمس".
- **`arpwatch`** — مراقبة ARP سلبية مستمرة؛ الوجه الكاشف لـ `mitm`.
- **`http`** — headers، بصمة السيرفر، سلاسل redirect.
- **OS fingerprinting** — انحرافات TTL/window/MSS/DF من ردود تُجمع أصلاً،
  تصدر كـ findings بدرجات ثقة.
- **`mdns` / `llmnr` / `nbns`** — نفس نمط `dns`/`dhcp` بالضبط: استعلام
  broadcast، أي رد من مصدر غير متوقع = poisoning (HIGH). رصد مباشر لهجمات
  Responder.
- **`ndp` + `dhcpv6`** — النسخة IPv6 الكاملة من رصد الـ rogue.
- **`stp` / `lldp` / `cdp`** — رصد ادعاءات L2 topology: root bridge جديد في
  STP؟ جهاز يبث CDP؟ live + offline pcap بنمط `wifi` الحالي.
- **DNS deep suite** — rebinding، حالة DNSSEC، سلوك NXDOMAIN، split-brain
  عبر مجموعات resolvers (توسيع `dns`).
- **DHCP fingerprinting** — تحديد الشركة من أنماط الـ options؛ تصنيف أقوى من
  ثنائية rogue/known.
- **mDNS/SSDP/UPnP discovery** — حصر الأجهزة والخدمات من الثرثرة المحلية.
- **Path MTU probe** — سلم DF-bits؛ يتناغم طبيعياً مع `frag_evasion`.
- **QUIC Initial crypto probe** — handshake كامل بعد نجاح Version
  Negotiation في `quicprobe`.
- **PQ-TLS probe** — ClientHello بحزم post-quantum hybrid
  (X25519MLKEM768) افتراضيًا + وضع "fragmented CH" مقصود: Hello الـ PQ
  يقفز من ~300 إلى ~1400 بايت فيعبر الـ MTU، ومسح PKIC على ملايين
  السيرفرات وثّق سيرفرات تفشل مع CH مجزّأ (وكسور حقيقية في Traefik/F5
  خلال 2026) — مقياس فوري لمنتصفات الشبكة التي ستنكسر مع انتشار PQ.
- **SCTP / raw protocols** — scapy يبني أي شيء؛ اجعل "probe جديد" شأناً من
  50 سطراً عبر عقد الـ plugins.

## 3 — منصة الـ Detection Engineering (المفرِّق الحاسم)

`synth` مولّد مُبذَّر اليوم. النسخة غير المحدودة **عدّة regression لقواعد
الـ IDS**:

> **تصويب تنافسي (بحث 2026-11):** Dalton (secureworks، مدرج لدى CISA) يغطي
> أصلًا "شغّل pcap ضد حساس IDS بـ Docker + قواعد ad hoc + فحص syntax" —
> فكرة "شغّل الـ pcap ضد الـ IDS" ليست فجوة. التمييز الحقيقي لـ vtknet:
> Dalton يستهلك pcaps جاهزة بلا مولّد — vtknet هو **مولّد الأرضية الحقيقية
> seeded (محادثات + sidecars expected findings)**: يعيد توليد نفس الهجوم
> بايت-ببايت من الـ seed، يغذّي Dalton نفسه كمنفّذ خارجي، ويوفّر scoring
> محليًا بلا infrastructure.

- **`synth --eval`** — pcap مولّد + sidecar ground-truth دخول؛ شغّل الـ IDS
  الهدف (Suricata/Zeek في الـ lab، أو Dalton كمنفّذ خارجي)؛ حلّل الـ alerts؛
  قارن المتوقع بالفعلي → مصفوفة true/false positives. غيّرت قاعدة؟ أعد
  التشغيل وشاهد ما كسرته. قابل للتشغيل كاملاً في CI.
- **الهجوم في سياقه** — خلفية "بني آدم" (DNS browsing، HTTP، NTP بتوقيت
  طبيعي) مع حقن الهجوم عند T+N ثانية: ما تحتاجه المكتشفات السلوكية
  (anomaly-based)، لا الـ signatures فقط. pcap واحد = baseline + هجوم.
- **سيناريوهات recon-agentic** — محاكاة recon مولّد من AI agents (توقيت
  بطيء غير منتظم، أنماط شبه أدوات، قرارات تتفرع): صنف كشف جديد طلبه الـ SOC
  في 2026 مع موجة الجيل الثالث agentic pentesting — وsynth seeded
  reproducible هو الموضع الطبيعي له.
- **جسر OpenAEV** — فئة Adversarial Exposure Validation صارت لها منصة
  مفتوحة قوية (OpenAEV من Filigran): صادِر سيناريوهات synth كمصدر
  سيناريوهات شبكية لها بدل منافستها — vtknet يولّد، المنصة توزع وتقيس.
- **آلة الزمن** — `--time-scale`، إزاحة/خلط الطوابع الزمنية، دمج عدة pcaps:
  اختبر كواشف النوافذ الزمنية دون انتظار زمن حقيقي.
- **سيناريوهات State-machine** — محادثات لا باكتس: ARP poison ثم تتبع
  حركة؛ slowloris؛ DNS NXDomain flood؛ handshake ثم tunnel. + **DSL تصريحي
  (YAML/JSON)** للسيناريوهات عبر نظام الـ plugins: سيناريو جديد بلا Python.
- **Chaos rewriting** — كرر/أعد ترتيب/اقطع/اقلب بايتات أي pcap: اختبار
  صلابة الـ parsers كميزة منتج.
- **OT/ICS** — سيناريوهات Modbus/TCP (write coil، function codes غير
  مصرح بها) وDNP3 (طبقات scapy contrib موجودة): lab اكتشاف للبنية
  التحتية الحرجة. niche شبه فارغ، ومقاس على الفلسفة تماماً
  (reproducible + evidence).
- **مصفوفة بصمات العميل TLS (JA3/JA4 matrix)** — الـ ClientHello مبني يدوياً:
  ولّد نفس الاتصال بعشرين بصمة عميل مختلفة (curl/Firefox/Java/python).
  اختبار: هل يميز monitoring الخاص بك بينهم؟ هل middlebox يكسر بصمة معينة؟
  + **JA4S للـ ServerHello**: بصمة الخدمة نفسها — رصد proxy/CDN/تطبيق
  غير متوقع خلف 443. **ملاحظة 2026:** JA3 رسميًا deprecated وJA4 أصبح
  mainstream، وJA5 ظهر كخليفة مقترح (ntop) بثبات أعلى ضد collision —
  اجعل المولّد scheme-agnostic: يخرج البصمات الثلاثة معًا ولا يحبس نفسه
  في schema واحد.
- **سيناريوهات Wireless** — beacon floods، حركة WPA3 transition-mode،
  انتهاكات PMF: وجه الاكتشاف في 802.11 بعد الـ deauth.

## 4 — الذكاء الزمني (history → عقل)

ذاكرة SQLite هي بذرة شيء نادر — انمِها دماغاً:

- **`report --diff :last`** — مقارنة تلقائية بآخر run لنفس command+target؛
  diff-by-default لا diff-by-run-id.
- **Flap detection** — بورت يتقلب open/closed عبر N من الـ runs هو بحد ذاته
  finding. التاريخ كدليل نشط لا أرشيف.
- **Anomaly scoring** — خطوط أساس إحصائية متعلمة من الـ history (RTTs،
  مجموعات البورتات، سلاسل الشهادات)؛ الانحراف يصبح finding.
- **Entity views** — خطوط زمنية لكل host، تاريخ لكل port؛ جدول الـ findings
  يصير knowledge graph للشبكة.
- **`watch` daemon** — profiles محفوظة (حزمة probes + جدول + سياسة diff)،
  إعادة تشغيل ذاتية، webhooks (Slack/Telegram) عند التغيير. vtknet من
  أمر one-shot إلى **network truth daemon** — بديل مفتوح لـ arpwatch/nzyme.
- **`report --timeline`** — صفحة HTML حية من `history.db`: أجهزة ظهرت
  واختفت، بورتات تغيرت عبر الزمن — البيانات موجودة ونادراً ما تُعرض بصرياً.
- **Tags & retention & export** — تسميات ("قبل تغيير الـ firewall")، نوافذ
  احتفاظ، تصدير CSV/Markdown.

## 5 — سلسلة الأدلة (verify → sign) — هوية الأداة

كل claim يحمل بايتاته بالفعل. خذها إلى النهاية:

- **`vtk verify`** — أعد فك كل بايتات evidence داخل تقرير، أكد أن الـ claim
  المطروح يطابق البايتات (port، kind، checksums)، وبلّغ عن أي خلاف.
  تقارير تراجع نفسها بنفسها.
- **Hashes & توقيع** — SHA-256 لكل evidence لحظة الولادة + توقيع ed25519
  لكامل الـ ScanResult (`cryptography` dependency أصلاً). تقارير pentest
  محصّنة ضد التلاعب — **لا أداة مفتوحة تفعل ذلك**.
- **تقرير HTML يشرح نفسه** — JS مدمج يفك الـ hex في المتصفح (طبقات + rebuild
  command) بلا أي تثبيت عند المستخدم؛ بدل الاقتطاع عند 96 حرفاً اليوم.
- **Evidence slices** — `pcap slice --finding ID --before 2 --after 5` يقصّ
  النافذة المحيطة بالدليل من capture كامل؛ أشجار evidence قابلة للفتح
  في التقرير.
- **جسر Wireshark** — لكل finding سطر "open in tshark" جاهز؛ تعميق التسليم
  للطبقة التفاعلية بدل استبدالها.
- **`vtk why` — إغلاق حلقة الدليل داخل النواة** — الدليل اليوم يثبت ما أُرسل
  وما رُصد على السلك، لكن "الـ probe أُرسل ولم يصل" يبقى بلا تفسير. افحص
  عدادات المسار المحلي (nftables/conntrack/`/proc`) ثم — اختياريًا وبنمط
  `pwru` — تتبع eBPF يجيب: هل خرج باكتي من الجهاز أصلًا؟ أين مات (qdisc
  drop؟ rp_filter؟ conntrack)؟ لا أداة scanning في الفضاء تقفل هذه الحلقة
  — والدليل يتكمل بدل أن يتوقف عند السلك.
- **طوابع reproducibility** — بصمة البيئة (kernel، iface، driver، إصدار
  scapy) داخل كل تقرير: نفس البايتات، أو فرق مُفسَّر.
- **`vtk kinds`** — سجل مركزي لأنواع الـ findings: معنى كل kind، الـ severity
  الافتراضي، الـ RFC المرجعي → JSON Schema وتوثيق تلقائي، وتوحيد labels قبل
  أن تتضاعف الوحدات والـ plugins.
- **`--dry-run --emit out.pcap`** — الـ dry-run يكتب الباكتس "التي كانت
  ستُرسل" في pcap للمراجعة — نفس انضباط الـ evidence قبل الإطلاق.

## 6 — التركيب والأسطح (composition)

- **قابلية تركيب Unix كاملة** — JSON على stdout، targets من stdin:
  `vtk sweep 10.0.0.0/24 --json | jq -r '.findings[].host' | sort -u |
  vtk scan --targets -`. الأوامر تصبح أفعالاً في جمل.
- **Playbooks** — YAML تصريحي: حزمة probes، profile التوقيت، سياسة diff،
  hooks الـ eval؛ `vtk run lab.yaml`. الـ daemon ينفذ الـ playbooks.
- **Python API parity** — كل ما يفعله الـ CLI قابل للاستيراد (`vtknet.api.run`)
  في الـ notebooks والـ pipelines.
- **Agent-first CLI + `vtk mcp`** — نموذج JSON المستقر مثالي للمنسقين.
  انشر JSON Schema، حافظ على مخرجات حتمية، أضف `--explain` (لماذا يهم هذا
  الـ finding — rule-based مع مراجع RFC). وأمر `vtk mcp`: يجعل inspect/pcap/
  report أدوات تُنادى من أي AI assistant. كل finding يعلّم.
- **SARIF + Markdown export** — SARIF يهبط مباشرة في GitHub Security tab؛
  Markdown للـ PRs.
- **`vtk flow-features`** — pcap → flow features حتمية (Parquet/CSV)
  بمفاتيح evidence: ناتج التصدير الذي يحتاجه مجال foundation models للـ
  traffic (Lens وغيرها، مجال بحث ساخن في 2026) — vtknet يغذي الـ ML
  research بلا أن يعتمد على أي موديل.
- **GitHub Action** — فحص الـ lab في CI ورفع النتيجة للـ Security tab:
  تبنٍّ فوري بلا جهد تشغيلي.
- **`doctor`** — جرد قدرات معلوماتي صرف: tcpreplay متاح؟ cryptography
  سليم؟ monitor ifaces؟ الـ lab حي؟ الـ DB سليم؟ أمر واحد يعرض كل ذلك.
- **config.toml + profiles** — `--profile stealth|lab|ci` يختار rate/timeout/
  workers جاهزة. + shell completion.
- **TUI (textual)** — dashboard حي لـ `watch`، ومتصفح لـ `report`.
- **Binary releases (pyinstaller)** — مستخدم بلا Python ينزّل ملفاً واحداً.

## 7 — الأداء (السقف: لا يوجد)

- **طموحات line-rate** — AF_XDP / PACKET_MMAP batch TX؛ لوحة نتائج عامة عبر
  `vtk bench` تقيس pps على loopback مقابل hping3/nmap/tcpreplay.
- **`vtknet mesh` — نقاط قياس موزعة** — N من الحساسات تشغل نفس حزمة probes؛
  النتائج تُدمج وتُقارن **عبر نقاط القياس**: أين عاشت التغييرة؟ (الطرف؟
  القلب؟ منتصف الطريق؟). قياس بأسلوب Atlas لكن self-hosted وبأدلة مرفقة.
  على الأرجح الفكرة الأكثر فرادة في هذا الملف.
- **pcapng** — timestamps بنانوثانية، comments داخل الـ capture (اكتب ملاحظة
  الـ finding داخل ملف الـ evidence نفسه)، captures متعددة الواجهات.
- **Ring buffer مع spill للقرص** — captures لا تسقط شيئاً لأيام.

## 8 — الـ Lab (كل شيء reproducible)

- **`lab genesis`** — شبكة مصغرة كاملة بأمر واحد: routers، targets، حاوية
  IDS، سيرفرات DNS/DHCP، خدمات. كل وحدة تشحن مع هدفها المفرد الملف
  (`tls_server.py`-style) فلا تحتاج Docker للاختبار.
- **Golden pipeline CI** — synth → replay على veth → Suricata → `synth
  --eval` → score → gate. حلقة الاكتشاف كاملة داخل PR check.
- **CMDB reconciliation** — قارن network truth مع Netbox (مسجل وموجود /
  مسجل ومفقود / موجود وغير مسجل): vtknet مدقق للـ CMDB.
- **سجل plugins** — وحدات مجتمع قابلة للاكتشاف؛ عقد API مُصدَّر للإصدارات.
- **`vtk learn`** — سيناريوهات الـ lab + inspect + شرح خطوة بخطوة = درس
  تفاعلي مدمج. أقوى جاذب لمستخدمين جدد.

## 9 — أوراق برية (wild cards)

- **Learn-and-craft** — أطعم pcap لبروتوكول مجهول؛ استنتج حدود الحقول
  وبنيته؛ أخرج مسودة scapy Packet class + قوالب fuzz. مساعدة reverse
  engineering مبنية على أنابيب capture+fuzz الموجودة أصلاً.
- **pcap surgery** — rewrite/anonymize/remap/merge/split كأوامر من الطبقة
  الأولى (آلة الزمن في §3 معممة).
- **Topology map** — الأدلة (ARP، فوارق TTL، traceroute، الردود) → خريطة
  GraphViz/Mermaid حية مع findings معلقة على العقد والحواف؛ Mermaid يُرسم
  مجاناً على GitHub.
- **اختبار تفاضلي A/B للشبكات** — حزمة probes واحدة عبر مسارين (واجهتان،
  VPN on/off، قبل/بعد قاعدة) وdiff جنباً إلى جنب. التحقق كسير عمل من
  الدرجة الأولى.
- **`fuzz --minimize`** — عند كسر جهاز: delta debugging يقلص الباكت إلى
  أصغر مجموعة حقول مسؤولة عن الانهيار — تقرير bug جاهز من أول تشغيل.
- **Stateful fuzzing** — طفرات داخل محادثة كاملة على `TCP_client` (بعد
  الـ handshake، في الـ app data) + **response-guided mutation**: رد غير
  معتاد = interesting، كثّف الطفرات حول ذلك الحقل. مكان لم يصل إليه
  hping3 إطلاقاً.
- **`vtk chaos`** — wrapper حول tc/netem (`--loss 5% --delay 40ms`) للـ lab:
  سلوك التطبيقات تحت عيوب الشبكة، مكمّل `synth --replay`.

---

## 10 — إضافات الجولة البحثية (بحث خارجي، 2026-11-11)

> أفكار نشأت من مسح السوق والأبحاث الحديثة — كلها غير مكررة في الأقسام
> أعلاه، وكل منها مؤسسة على فجوة مؤكدة لا أداة تملأها.

### 10.1 `tls --pq` — جاهزية ما بعد الكم (فرصة توقيت نادرة)
X25519MLKEM768 صار المعيار النهائي المتفق عليه ([RFC 10024]) والخيار
الافتراضي للمتصفحات والـ CDNs، وموجة الترحيل في منتصفها. الموجود في السوق
أدوات hosted للمواقع (Wiz، CertKit، SSL Labs) — لا توجد أداة toolkit-level
قابلة للبرمجة تحمل evidence. عندنا الـ ClientHello مبني يدوياً أصلاً:
أضف مجموعة PQ إلى supported_groups واقرأ ما تفاوض عليه السيرفر →
findings (`tls.pq.ready` / `tls.pq.legacy`) بأدلة البايتات. بحث داخلي
للترحيل + تقرير مميز. **جهد يوم — أعلى quick win بحثي.**

### 10.2 `tls --ech` — اختبار ECH (RFC 9849)
ECH صار معياراً نهائياً، ويعمي middleboxes وfirewalls المعتمدة على SNI
(Cisco وAPNIC وثقا الأمر). البحث أكد: **لا توجد أداة اختبار مخصصة لـ ECH**
— فجوة حقيقية. الـ builder اليدوي يسمح: ClientHello بامتداد ECH + outer
SNI عام → هل يدعم السيرفر ECH؟ هل يقتلها middlebox في الطريق؟ **وهل
أدوات المراقبة عند المستخدم صارت عمياء؟** — اختبار أثر الاكتشاف
(detection-impact) لا يوفره أحد، وهو بالضبط أرض detection engineering.

### 10.3 `synth --eval` + محوّلات datasets عامة
تعزيز لفكرة §3: استيراد الـ datasets المسماة العامة (CIC-IDS2017/2018،
ومجموعة [Muñoz-Calle 2026] الـ ATT&CK-labeled pcapng) إلى صيغة sidecar
ground-truth → corpus اختبار فوري للـ eval بلا توليد. والاتجاه المعاكس:
وسم سيناريوهات synth بأرقام تقنيات MITRE ATT&CK، وربط findings بالضوابط
المقابلة من D3FEND داخل `--explain`. البحث أكد كذلك: **لا يوجد إطار
مفتوح موحد لاختبار regression لقواعد Suricata/Zeek** (الموجود generation
مثل RuleAutoPilot/RuleXploit، لا regression من pcap+ground-truth) —
الفجوة التي يحتلها `--eval` حقيقية وموثقة.

### 10.4 `--adversarial` — اختبار صلابة المكتشفات ML
الأبحاث الحديثة ([arXiv 2026]: نسب تهريب >97% ضد ML-NIDS، و[NIST SP
2400-102] أقننة المنهجية) تظهر أن robustness testing للمكتشفات السلوكية
صار مطلباً قياسياً. vtknet يملك البنية كلها: chaos rewriting +
attack-in-context + sidecars. المنتج: `synth --eval --adversarial` —
اضطرابات traffic-space تلقائية (تقسيم/تكرار/إعادة ترتيب/جيت.timing/
حشو) على أثر الهجوم، وقياس: هل يظل الكاشف صادقاً؟ مادة بحثية قابلة
للنشر، وميزة لا يمتلكها أي إطار IDS حالي.

### 10.5 `policy` — التحقق من نية الـ Firewall على السلك
اقرأ ruleset الـ nftables/iptables → استنتج السلوك المتوقع → نفّذ probes
فعلية → diff: **النية vs الواقع** ("القاعدة مكتوبة لكن مش منفذة فعلاً").
[Batfish] يتنبأ من الإعدادات؛ vtknet يتحقق بأدلة من السلك — مكمل لا منافس.
البحث أكد غياب أداة مفتوحة تتحقق بالنشاط الفعلي. يتغذى من A/B differential
(§9) ومن Engine.

### 10.6 `dns --intercept` — كشف اختطاف DNS الشفاف
منهجية [USENIX '18 / IMC '21]: نفس الاستعلام عبر plain DNS مقابل DoT/DoH
ومقابل resolvers معروفة → انحراف أو redirect = proxy شفاف يختطف (راوترات
البيت وأشباه الموصلات ISPs). نمط divergence الموجود أصلاً في `dns` —
امتداد طبيعي يفتح use case جديد كلياً: "افح شبكتك المنزلية".

### 10.7 `amplify` — تدقيق ذاتي للتضخيم
probes لسيرفرات المستخدم نفسها (DNS ANY، NTP monlist، memcached get،
SNMP bulk) → قياس معامل التضخيم من الردود الفعلية بأدلة. تدقيق ذاتي
ضد reflection — فحص يستقيم مع فلسفة الأداة (كل رد دليل) وينتج findings
واضحة ("سيرفرك يضخم 40x").

### إضافات صغيرة من نفس الجولة
- **`time` (نمط divergence):** نفس سؤال الوقت لعدة NTP/PTP servers →
  انحراف = مصدر وقت مريب (يغذي `watch` وanomaly scoring).
- **BLE census (wild card):** scapy معه طبقات bluetooth — جرد أجهزة BLE
  ورصد تزوير beacons؛ وحدة لاسلكية ثانية بلا أثر منافس.
- **eBPF observer (moonshot):** مراقبة سلبية على مستوى الـ socket
  (`vtk observe`) — Linux-only كـ optional dependency قصوى.

[RFC 10024]: https://www.rfc-editor.org/info/rfc10024
[Muñoz-Calle 2026]: https://www.sciencedirect.com/science/article/pii/S0167404826003652
[arXiv 2026]: https://arxiv.org/html/2609.06012v1
[NIST SP 2400-102]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.2400-102e2026.ipd.pdf
[Batfish]: https://batfish.readthedocs.io
[USENIX '18 / IMC '21]: https://chaoyi.lu/paper/sec18-intercept.pdf

---

## 11 — جولة خارج الصندوق ذاتية (من فهم البنية نفسها، 2026-11-11)

> أفكار وُلدت من الأصول التي بُنيت فعلاً في 0.8.0: سلسلة الأدلة الموقعة،
> سجل الـ kinds، الذاكرة الزمنية، correlation الردود في capture، والبروب
> الهجين. كل فكرة هنا قابلة للبناء بأجزاء موجودة — والتحقق الأكاديمي أكد
> أن الفضاء منتجياً فارغ.

### 11.1 Merkle-ized findings — إفصاح انتقائي موقّع (امتداد مباشر للتوقيع)
شجرة Merkle فوق hashes الأدلة في كل run؛ الجذر يدخل في الـ DSSE statement.
`vtk verify --prove FINDING_ID` يخرج **إثبات احتواء** (inclusion proof) —
تُسلّم نتيجة واحدة مع إثباتها لطرف ثالث دون كشف باقي التقرير (بأسلوب
Certificate Transparency). البناء: hashlib + الـ sha256 المختومة أصلاً.
**نقطة لا يمتلكها أي scanner ولا أي attestation tool للشبكات.**

### 11.2 `fidelity` — تدقيق سلامة المسار بالبايت
A يرسل بايتات معلومة → B يستقبل → C يستمع على الطريق؛ hash المُرسل مقابل
hash المرئي عند C مقابل hash المُستقبل عند B. أي فرق = middlebox يعيد
الكتابة بسرية (MSS clamp، قص payload، قتل TCP options، اعتراض أثناء
الطيران). سلسلة الأدلة تجعله طبيعياً: `fidelity.mangled` بحاشيتين
كأدلة. الأصول الأكاديمية: [tracebox] (hop-by-hop) وTCPExposure وYarrpbox
(~10% من مسارات IPv4 فيها rewriting) — **ولا توجد أداة جاهزة مهيمنة
للتدقيق on-path**؛ إنه pipeline مخصص حتى اليوم.

### 11.3 `pathprint` — شخصية المسار (atlas الـ middleboxes)
جنونية مُقننة: مجموعة اختبارات لأنماط الفشل المعروفة — fragmented
ClientHello (عندنا)، segments متداخلة، IP options، urgent pointer،
zero-window، سلوك TTL-expiry، GREASE values (روح RFC 8701). الخرج:
بصمة "شخصية" لكومة الـ middleboxes في المسار تُخزن في history —
**أي تغيير جهاز في المنتصف يظهر كـ diff في الشخصية**. يتغذى من
frag_evasion وبروب PQ الموجودين.

### 11.4 `bisect` — هندسة عكسية للقاعدة الحاجزة
عينتان: مسموح وممنوع. ثنّي على أبعاد البروب (port، TTL، payload، flags،
source range) حتى أصغر خصائصة فاصلة — الخرج: "القاعدة الحاجزة تطابق:
dport 8443 AND ttl<10" مع مصفوفة البروبات كأدلة. أرضية أكاديمية:
أوراق last-matching-rules discovery — **لا يوجد CLI منتج يجعلها روتيناً**.
يحوّل "أنا ممنوع" إلى "أعرف بالضبط لماذا".

### 11.5 `vtk assert` — الشبكة كـ desired-state
YAML من الوعود: "host X:443 مفتوح، شهادته >30 يوماً، سيرفر DHCP واحد
بالضبط". أخضر/أحمر كـ exit code؛ CI ضد الـ lab؛ الـ watch daemon ينفذها
بجدول. البروبات تتحول من "مولّدات تقارير" إلى **مدقِّقة وعود** —
Terraform-plan لكن للشبكة الحية.

### 11.6 ledger reconciliation — قيد مزدوج للشبكة
كل باكت مُرسل = مدين؛ كل باكت مُلتقط = دائن؛ `match_replies` (موجود!) يقرّن.
**دائن بلا مدين = حركة غير مُلتمة** — "الشبكة كلّمت أولاً" — فئة findings
جديدة تلتقط scanners الآخرين والـ worms وردود الأشباح. تنفيذها جناح جانبي
أثناء أي run: capture بـ BPF على عناويننا + reconcile. فلسفياً مثالية:
"كل شيء دليل" → "كل شيء يجب أن يتوازن".

### 11.7 blindspots — التقرير يعلن حدود معرفته
كل run يصدر خريطته العمياء: ما لم يُفحص، وما هو غير مؤكد ولماذا
(rate-limited؟ filtered؟ ميزانية timeout؟). "open|filtered" تتحول من
تردد إلى **قياس صريح للجهل**. لا أحد يفعلها — التقارير تتصنّع عصمة.
أصدق تقرير في السوق.

### 11.8 evidence is executable — الدليل هو البرنامج
`vtk replay-finding <id>`: أعد إرسال البايتات نفسها من دليل أي finding.
الـ mutant المكسور محفوظ كدليل أصلاً في fuzz — تعميم: **كل دليل قابل
لإعادة التنفيذ**. الدليل يتوقف عن كونه توثيقاً ويصبح البرنامج نفسه.

### 11.9 forensic annotator — أي pcap يصبح تقرير vtknet موقّعاً
صفر باكتس: خذ capture من أي أداة، مرره عبر parsers الـ banner/kinds/
fingerprints، وأخرج تقرير vtknet موقعاً. الأداة تصبح **معلِّقاً جنائياً
لـ pcaps الآخرين** — ومعظم الوحدات لها نصف offline أصلاً؛ الباقي wiring.

### 11.10 detection dojo — تدريب القواعد بتصحيح آلي
حزم سيناريوهات + عدّة الـ eval = تحديات مصححة آلياً: "اكتب قاعدة Suricata
تلتقط frag_evasion بالـ seed 1337" — التصحيح لحظي (TP/FP matrix) ولوحة
نتائج لكل seed. دوّار تبنٍّ مجتمعي يعتمد على §3.

### بذور أصغر من نفس الجولة
- **`report --as-of DATE`**: إعادة بناء لقطة الشبكة في تاريخ ما من history.
- **سجل سردي بلا LLM**: "هذا الأسبوع: 3 hosts جدد، شهادة gw تغيرت،
  8443 اختفى" — قوالب فوق الـ diff.
- **kinds كسجل عام**: نشر السجل machine-readable ليعيد أدوات أخرى إصدار
  findings متوافقة — السجل يصبح معياراً.
- **attestation ضد harvest-now-decrypt-later**: التوقيع المؤرَّخ يثبت
  "كنا نعرف حالة هذه الشبكة في تاريخ كذا" — امتداد سردي لـ PQ+signing.

[tracebox]: https://dl.acm.org/doi/pdf/10.1145/2504730.2504757

---

## الأولويات (رأي قابل للنقاش — لا شيء خارج النطاق)

| # | الفكرة | لماذا |
|---|--------|-------|
| 1 | `synth --eval` harness (§3) | Dalton يغطي التنفيذ لا التوليد — vtknet مولّد الأرضية الحقيقية seeded الذي يغذيه؛ الأصول جاهزة (synth + sidecars) |
| 2 | `watch` daemon (§4) | يحوّل الأداة من one-shot إلى منتج يعيش وينبّه |
| 3 | IPv6 suite (§1) | الفجوة البنيوية المجدولة في الكود نفسه + rogue RA فريد |
| 4 | Evidence verify + signing (§5) | يقوّي أكثر ما يميز vtknet — لا أحد يفعله |
| 5 | `vtknet mesh` (§7) | قياس موزع self-hosted بالأدلة — الأكثر فرادة |

+ من الجولة البحثية (§10): `tls --pq` يدخل Quick wins فوراً (فرصة توقيت)،
و`synth --eval --adversarial` مرشحة Big bets (مادة بحثية قابلة للنشر).

## Quick wins (يوم جهد، أثر فوري)

1. `banner` — أرخص وحدة، أعلى مردود.
2. `report --diff :last` — امتداد طبيعي للـ store الحالي.
3. SARIF exporter — ملف واحد جديد في `core/report.py`.
4. SHA-256 على الـ evidence — أول لبنة في سلسلة التحقق.
5. `--dry-run --emit out.pcap` — امتداد مباشر للـ dry-run.
6. `vtk kinds` — توحيد الـ labels قبل أن تتضاعف الوحدات.
7. PQ-TLS probe (نسخة أولى) — امتداد مباشر لـ `tlsprobe`: نفس الـ
   ClientHello اليدوي بحزمة X25519MLKEM768 + وضع fragmented CH.
7. `tls --pq` (§10.1) — امتداد supported_groups في الـ builder موجود أصلاً.

---

---

## المسار التنفيذي المعتمد

الوثيقة سقفها مفتوح، والتنفيذ يمشي في sprints محددة — كل sprint يُغلق بـ
pytest + ruff أخضرين وتحديث `CHANGELOG.md`:

| Sprint | المحتوى | الحالة |
|--------|---------|--------|
| **Sprint 1** | الـ quick wins السبعة: SHA-256 evidence، `vtk kinds`، `report --diff :last`، SARIF، `--dry-run --emit`، وحدة `banner`، PQ-TLS v1 | **قيد التنفيذ (2026-11-11)** |
| **Sprint 2** | `synth --eval` MVP: scoring محلي ضد Suricata + تغذية Dalton كمنفّذ خارجي | مخطط |
| **Sprint 3** | `watch` daemon MVP: profiles + diff-by-default + webhook واحد | مخطط |
| **Sprint 4** | IPv6 suite: NDP sweep + ICMPv6 + scan6 + rogue RA | مخطط |
| **Sprint 5** | `vtk verify` + توقيع ed25519 | مخطط |

قواعد التحديث: لا يُحذف شيء من هذا الملف — البند المنفذ يُعلَّم بأنه انتقل
إلى `CHANGELOG.md` بإصداره، والجديد يُضاف بمرجعه (قراءة كود أو بحث خارجي).

*آخر تحديث: 2026-11-11 — Sprint 1.*
