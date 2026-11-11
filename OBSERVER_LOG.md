# ملاحظات المراقبة — سجل الرصد والبحث (وضع قراءة فقط)

> **وضع العمل:** هذا الملف كُتب أثناء مراقبة وكيلٍ آخر يعمل على نفس المشروع.
> **قاعدة صارمة: لا تعديل — لا حذف — لا لمس لأي ملف مصدر.** كل ما في هذا
> الملف ملاحظات، وتحقق بحثي، وحكم مستقل. مُنشأ في 2026-11-11 (07:58 → 08:35+
> بتوقيت الجلسة)، ويُحدَّث أولًا بأول مع كل محطة رصد.

---

## 1. الخط الزمني للرصد (أول بأول)

| التوقيت | ما رصدته |
|---------|----------|
| 07:43–07:55 (قبل بدء مراقبتي) | Sprint 1 الأساسي كان قد اكتمل (evidence sha256، kinds، diff :last، SARIF، emit، banner، PQ v1) — ثم ظهرت آثار وكيلٍ آخر: `core/converse.py` + `tests/test_review_fixes.py` (ملفات لم أكتبها أنا) |
| 07:50 | `converse.py`: قراءة **bounded** من لينكات scapy — thread قارئ + إغلاق اللينك من الخارج عند انقضاء المهزة. يغلق ثغرة حقيقية: `recv()` المفتوحة كانت تُعلّق البروب للأبد مع سيرفر صامت |
| 07:53 | `test_review_fixes.py`: 17 اختبار مراجعة — قفل IANA المزدوج (4588 عشري = 0x11EC)، ServerHello يدوي + `FakeLink`، واختبار **anti-hang** يقيس الزمن الفعلي (< 5 ثوانٍ) |
| 07:56–08:04 | `tlsprobe.py` يتوسع (20.9KB): `MLKEM768_GROUP = 0x11EC` مع تعليق تحذيري صريح، `parse_serverhello_selected_group` (bytes walk آمن)، تصنيف جديد **`tls.pq.fallback`**، وربط `link_recv_bounded` في المسارين العادي والـPQ |
| 08:08 | `report.py`: **primaryLocationLineHash** ثابت (sha256 من ruleId+host+port+module+occurrence)، `security-severity` على مستوى الـrules، region صحيح (startLine:1) — طبّق توصيات SARIF الاحترافية |
| 08:24 | `kinds.py`: من 49 إلى **65 kind** — سجل verify.*/blindspot.*/assert.*/replay.sent/ledger.unsolicited |
| 08:24–08:27 | **6 ملفات core جديدة**: `signing.py` (DSSE v1 حرفيًا)، `verify.py`، `ledger.py`، `blindspot.py`، `assertions.py`، `replay.py` — قفزة تعني دخول Sprint 5 (verify/sign) + إضافات خارج الخارطة |
| 08:27+ | الحالة: **282 اختبارًا ينجحون** (كانوا 223) — لكن **ruff فيه 13 خطأ** مؤقتة (شغل جاري) |

---

## 2. الحكم الفني: هل ماشي صح؟

**نعم — صحيح فنيًا على كل المحاور التي تحققت منها بالتوازي:**

1. **IANA 0x11EC**: تحققت من مصدر أولي (IANA TLS Parameters، مرجع RFC 9847 /
   draft-ietf-tls-mlkem): X25519MLKEM768 = **4588 عشري = 0x11EC**. الكود القديم
   (0x4588 — خطئي أنا في Sprint 1) كان سيُعلن group غير مُسجّل ويجعل كل سيرفر
   يبدو post-quantum زورًا. إصلاحه مع regression test مزدوج (عشري + hex) هو
   الأذكى الممكن.
2. **`parse_serverhello_selected_group`**: يطابق RFC 8446 §4.2.8 بالظبط —
   ServerHello key_share = entry واحد: `selected_group(2) + key_len(2) + key`،
   أي أن أول بايتين من الامتداد 0x0033 هما المجموعة المُختارة. الـbytes walk
   محدود الحدود ويرجع `None` على أي bytes معادية — لا exceptions.
3. **`link_recv_bounded`**: حل المشكلة الصحيح (thread + إغلاق تحت القارئ الذي
   يُفكّ الـautomaton) — نفس نمط المكتبات المجرّبة.
4. **`dnsprobe.extract_answers`**: توحيد سلوك scapy 2.8 (PacketListField) مع
   القديم (سلسلة payloads) وعدم الثقة في `ancount` المزيّف — متسق تمامًا مع
   فلسفة 0.7.0 (hostile-input hardening) ومؤكد باختبارين جديدين.
5. **DSSE**: الـPAE مطابق للسبيك حرفيًا، و`payloadType` مخصص
   (`application/vnd.vtknet.report.v1+json`) وليس `application/json` العام —
   تفصيل يحذر منه السبيك صراحة، وهو فرق الـtop-1%.
6. **CI**: actions مثبتة بـSHA + صلاحيات صريحة + ubuntu-22.04 لمصفوفة py3.9 —
   تحصين سلسلة توريد فوق المطلوب.

## 3. هل بينفذ بأذكى طريقة؟ (نقاط فاق بها التخطيط المكتوب)

1. **`tls.pq.fallback` كـfinding منفصل**: نسختي كانت تكتفي بـnegotiated/alert؛
   هو يفرّق "السيرفر شاف عرض PQ واختار classical" — إشارة توافق أنظف بكثير.
2. **`verify.py` يتسامح مع تقارير ما قبل 0.8.0** (`no_hash` بدل الفشل) — قرار
   هجرة صحيح يمنع كسر المستخدمين الحاليين.
3. **`blindspot.py` — فكرة بلا مثيل في السوق**: التقرير يعلن **حدود معرفته**
   بنفسه (ports غير محلولة، hosts صامتة) كـfindings معرفية — أصدق تقرير ممكن.
4. **`ledger.py` — القلب العكسي**: بدل "من رد علينا؟" يسأل "**من كلمنا من
   غير استدعاء؟**" — مسك دفاتر مزدوج للسلك، بيبني على capture الموجود أصلاً.
5. **`assertions.py` بـJSON لا YAML**: desired-state + خروج 1 كـCI gate بدون
   أي dependency جديد — متسق مع خفة المشروع.
6. **`replay.py` — الدليل قابل للتنفيذ**: إعادة إطلاق الـmutant الكاسر
   بايت-ببايت من التقرير نفسه — يغلق حلقة evidence→action.

**الخلاصة:** الاتجاه صحيح، والتنفيذ في 6 نقاط ملموسة **أذكى من الخطة المكتوبة**.

---

## 4. مخاطر وملاحظات نقدية (للمناقشة — لا تنفيذ من طرفي)

- ⚠️ **ruff: 13 خطأ حاليًا** — لازم يتنضف قبل إغلاق أي مرحلة (كان نظيفًا في
  نهاية Sprint 1).
- ⚠️ **الوثيقة الرسمية متأخرة عن الواقع**: `IDEAS.md` (المعتمدة كخارطة طريق)
  لا تعرف بشيء من signing/verify/ledger/blindspot/assert/replay — 6 ميزات
  خارج المسار التنفيذي المتفق عليه. القاعدة المكتوبة في الوثيقة نفسها تقول:
  "الجديد يُضاف بمرجعه" — لم يحدث بعد.
- ⚠️ **انقلاب ترتيب الأولويات دون توثيق**: Sprint 5 (verify+sign) نُفِّذ قبل
  Sprint 2 (`synth --eval`) الذي هو الأولوية رقم 1 في جدول IDEAS.md. التدفق
  مفهوم (حماس المراجعة)، لكن القاعدة الأفضل: توثيق السبب في الوثيقة أو العودة
  لـSprint 2 فورًا — هو البند ذو القيمة السوقية الأعلى والمعلّق.
- ⚠️ **ECH: صفر أثر في الكود حتى لحظة الكتابة** (grep نظيف) — نصف البريف
  الثاني لم يبدأ بعد.
- ⚠️ **SARIF region**: `startColumn=port` (تنفيذ Sprint 1 — خطئي) كان غير
  صحيح schema-wise؛ الصحيح الجديد `startLine:1 + startColumn:1` آمن لكنه
  placeholder — المستقبل الأفضل: `logicalLocations` (kind: resource) مع
  خاصية properties تحمل host/port، مع العلم أن GitHub لا يقرأ logicalLocations
  (موجودة في message وfingerprint حاليًا — مقبول).
- ⚠️ **بحث PQ/ECH عبر الوكيل**: أُطلق 3 مرات (مقاطعة مستخدم → فشل تنفيذ →
  إعادة إطلاق ناجحة لم تعد بعد). الفجوة غطيت بتحقق مباشر من طرفي (§6).

---

## 5. نتائج البحث 2 — SARIF / taxonomy / signing (الوكيل أكمله)

التقرير الكامل (23.5 ألف حرف، كل claim بمصدره) محفوظ في:
`.zwork/runs/0deee8e5/1-研究员.md` — الخلاصة التنفيذية:

- **GitHub يقرأ `partialFingerprints.primaryLocationLineHash` فقط**؛ بدون
  fingerprint ثابت = alerts مكررة عبر الruns. الـuuid العشوائي (تنفيذ Sprint 1
  — خطئي) مخالف لغرض §3.27.17. النمط الصحيح: sha256(ruleId+host+port+module+
  occurrence) بنمط osv-scanner — **الوكيل طبّقه قبل وصول البحث** (استنتجه من
  كود CodeQL/osv-scanner مباشرة).
- **`security-severity`** (نص 0.0–10.0) هو المفتاح الرسمي لدرجة الـalert في
  GitHub؛ `precision` للترتيب؛ `problem.severity` لغير الأمني.
- **مستويات Trivy**: CRITICAL/HIGH→error، MEDIUM→warning، LOW/UNKNOWN→note؛
  `none` ممنوع للمخرجات الموجهة لـGitHub.
- **التاكسمي**: OSV = تطور **additive-only** + `schema_version` + بادئة `x_`
  للخصوصي؛ Semgrep = schema مُثبت بـ`$id`؛ nmap = سجل مركزي بمراجعة. توصية
  2026: JSON Schema **2020-12** للمشاريع الجديدة (OSV/STIX)، draft-07 مقبول
  للتوافق (vtknet عليه draft-07 — نقطة قرار موثقة لا عيب).
- **in-toto Statement v1**: `_type` ثابت، `subject` يتطلب `digest` (الاسم
  اختياري — مثال السبيك نفسه: vulnerability scan)، `predicateType` URI مخصص،
  `predicate` كائن حر.
- **DSSE PAE بالبايتات**: `DSSEv1 + SP + LEN(type) + SP + type + SP +
  LEN(body) + SP + body` (مع test vector رسمي)، الenvelope: payloadType/
  payload(b64)/signatures، والتوثيق ed25519 عبر `Ed25519PrivateKey.sign(PAE)`
  (64 بايت). المفتاح في `~/.vtknet` بصلاحيات 0600، keyid غير مُصادق عليه
  (hint فقط).
- **الفراغ السوقي مؤكد**: لا توقيع تقارير scan في nmap/GVM/Nessus (بحث موثق
  داخل التقرير)؛ أقرب prior art = cosign/Trivy attestations (مقيدة بالحاويات).
  vtknet يملك المساحة بحرية.

## 6. نتائج البحث 1 — PQ/ECH (تحقق مباشر مني؛ تقرير الوكيل لم يعد بعد)

- **IANA**: X25519MLKEM768 = 4588 = **0x11EC** (مؤكد — iana.org، مرجع RFC 9847).
- **ServerHello key_share** (RFC 8446 §4.2.8): entry واحد — `group(2) +
  len(2) + key`؛ المجموعة المختارة = أول بايتين. تنفيذ الكود صحيح.
- **الأحجام**: client encapsulation key = 1184B، server ciphertext = 1088B
  (FIPS 203) — الكود يستخدم 1184 للجهة الصحيحة.
- **scapy 2.8 محليًا**: `TLSServerHello` لا يفك key_share (يعيد الامتداد خامًا)
  — الbytes walk هو القرار الصحيح (مؤكد بالفحص المباشر).
- **`ech_required` = 121 (0x79)**: مسجل في TLS Alerts عبر إصدارات esni
  (§11.2) ونُشر RFC 9849 في مارس 2026. الرقم ثابت عبر الإصدارات؛ يُستحسن
  إعادة تأكيد بسطر واحد قبل الاعتماد في كود إنتاج ECH.
- **ECH 2026 عمليًا**: curl `--ech` (تجريبي منذ 8.8.0)، OpenSSL أعلنت دعم ECH
  رسميًا 2026-03-11، NGINX 1.29.4 (2026-02-19) يدعم ECH shared-mode مع اختبار
  محلي بcurl، Cloudflare في الإنتاج.
- **GREASE ECH** (esni-17 §6.2): العملاء بلا إعدادات يرسلون امتداد ech وهميًا
  للحفاظ على العبور — probe يبث GREASE ويصغي لـech_required = كشف دعم/قتل
  وسطي بلا DNS.
- **استنتاج vtknet**: مسار ECH الكامل (GREASE + 121 + قراءة HTTPS/SVCB retry
  configs) فئة لا تغطيها testssl.sh كصنف مستقل حتى الآن — فرصة أول-متحرك.

---

## 7. الحكم النهائي للمالك

- **صح؟** نعم — 6/6 محاور فنية تحققت منها مباشرة وكلها سليمة.
- **أذكى؟** نعم — 6 نقاط فاق بها الخطة المكتوبة (§3)، وأهمها blindspot وreplay
  وledger: ثلاث أفكار لم تكن في IDEAS.md أصلًا وهي قابلة للتسجيل كأفكار جديدة
  موثقة.
- **ما الذي يحتاج تدخل المالك؟** ثلاثة فقط: (1) تنضيف ruff قبل الإغلاق،
  (2) مطابقة IDEAS.md/CHANGELOG مع الواقع الجديد (الوثيقة الرسمية لا تتخلف)،
  (3) قرار واعٍ: نعود لـSprint 2 (`synth --eval`) بعد هذه الموجة — أم نوثق
  سبب تقديم Sprint 5.
- وضعي: **مستمر في المراقبة فقط** — لا لمسة واحدة مني على الكود طالما الوكيل
  يعمل.

*نهاية السجل — يُحدَّث عند كل محطة رصد جديدة.*
