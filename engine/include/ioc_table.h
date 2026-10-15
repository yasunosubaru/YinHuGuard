// engine/include/ioc_table.h
//
// 银狐已确认落点的 IOC 表。**每一项都带出处。**
//
// 为什么放在 C++ 而不是 rules.json：这些不是用户可调的判据旋钮，而是从厂商
// 报告正文里一条条抄出来的事实。混进 rules.json 会让人以为可以随意删改，
// 而「随手删掉一条就不会再报」对这个工具来说是最不该有的自由度。判据的
// 可调部分（解释器关键字、路径白名单）仍然在 rules.json。
//
// 收录标准：只在有厂商报告或应急响应公开确认时才收录。**查不到出处的民间
// 脚本条目一律不收** —— 凭空造 IOC 等于凭空造误报，而上游「解禁杀毒软件.bat」
// 正是这么干的（它把 vafdska / MiniFilterDrv 当驱动删，把微软卷影复制服务
// 的数字混淆名 MicrosoftSoftware2ShadowCop4yProvider 当木马）。
//
// 匹配一律小写不敏感。Windows 路径与服务名本来就不分区分大小写，小写化一侧
// 是最省事且不会漏配的做法。

#ifndef YH_IOC_TABLE_H_
#define YH_IOC_TABLE_H_

#include <cstddef>

namespace yh {
namespace ioc {

struct NameRule {
  const char* name;         // 服务名 / 驱动名 / 注册表值名
  const char* evidence_url; // 厂商出处，报告里可点
  const char* note;
};

// 2) 驱动服务。BYOVD 全家：都被合法证书签过名，签名校验挡不住，
//    只能靠已知的文件名认。共同目的只有一个：把 PID 送进内核调
//    ZwTerminateProcess，杀用户态杀不掉的进程。
//    Check Point 2025-09 / 2026-07、Cato CTRL、看雪 2026-02。
const NameRule kDriverNames[] = {
    {"amsdk", "https://thehackernews.com/2025/09/silver-fox-exploits-microsoft-signed.html",
     "WatchDog/Zemana AntiMalware SDK 1.0.600，微软签名，不在易受攻击驱动黑名单"},
    {"wamsdk", "https://thehackernews.com/2025/09/silver-fox-exploits-microsoft-signed.html",
     "Zemana SDK 1.1.100，改 1 字节时间戳字段绕过签名覆盖，签名仍有效而哈希变了"},
    {"zam", "https://thehackernews.com/2025/09/silver-fox-exploits-microsoft-signed.html",
     "老版 Zemana 驱动，打 Win7 兼容路径"},
    {"wsftprm", "https://cato-ctrl.com/",
     "此前已知的合法易受攻击驱动"},
    {"bootrepair",
     "https://thehackernews.com/2026/07/silverfox-targets-japanese-manufacturer.html",
     "2026-07 新出现，Zeon Corporation 的 ConvertToPDF.exe / PDFDirect.exe 侧载"},
    {"enportv",
     "https://thehackernews.com/2026/07/silverfox-targets-japanese-manufacturer.html",
     "同上，PDFDirect.exe 侧载"},
    {"stprocessmonitor", "https://bbs.kanxue.com/thread-290009.htm",
     "Safetica 驱动，CVE-2025-70795"},
    {"truesightkiller", "https://bbs.kanxue.com/thread-290009.htm",
     "关闭杀软并下载创建计划任务的 shellcode"},
};

// 3) 注册表里存的载荷（不是启动项，但是清理目标）。
//    Zscaler ThreatLabz / Atos / Cato CTRL 确认。
const NameRule kRegistryPayloadKeys[] = {
    {"HKLM\\SOFTWARE\\IpDates_sun",
     "https://cato-ctrl.com/",
     "存 shellcode 与配置"},
    {"HKLM\\SOFTWARE\\IpDatespecial", "https://www.secrss.com/articles/79443",
     "奇安信记录的注册表值，处置动作 101"},
    {"HKCU\\SOFTWARE\\Magisk", "https://atos.net/wp-content/uploads/2026/07/SilverFox_ValleyRAT_AnyDesk_Campaign.pdf",
     "Winos 加载器，值名 ring3_username 里被写入当前用户名"},
};

// 标记串。LZNT1 解压前的兄弟要搜索这个字符串来定位配置区。
const char* const kMarkerString = "FaCai2024";

// 4) 计划任务名（伪装成系统任务）。Nextron / Atos / 奇安信 / 北大计算中心通告。
const NameRule kTaskNames[] = {
    {"WindowsPowerShell.WbemScripting.SWbemLocator",
     "https://www.nextron-systems.com/2025/11/28/thor-vs-silver-fox-uncovering-and-defeating-a-sophisticated-valleyrat-campaign",
     "任务名伪装"},
    {"HandleCommand",
     "https://atos.net/wp-content/uploads/2026/07/SilverFox_ValleyRAT_AnyDesk_Campaign.pdf",
     "任务名伪装"},
    {"Windows Update Helper",
     "https://atos.net/wp-content/uploads/2026/07/SilverFox_ValleyRAT_AnyDesk_Campaign.pdf",
     "description 字段伪装，author 填 Microsoft Corporation"},
    {"WindowsSafe", "https://www.secrss.com/articles/79443", "任务名伪装，每 1 分钟触发"},
    {".net framework ngen vtie", "https://www.secrss.com/articles/79443",
     "任务名伪装，XML 配置在 %LOCALAPPDATA%\\PolicyManagement.xml"},
};

// XML 定义文件名。计划任务不直接拉木马时，会先落这些 xml / vbe。
const NameRule kTaskDefinitionFiles[] = {
    {"Pocy", "https://www.nextron-systems.com/2025/11/28/thor-vs-silver-fox-uncovering-and-defeating-a-sophisticated-valleyrat-campaign",
     "任务 XML 定义文件，落在 C:\\ProgramData\\"},
    {"Pocy1", "https://www.nextron-systems.com/2025/11/28/thor-vs-silver-fox-uncovering-and-defeating-a-sophisticated-valleyrat-campaign",
     "同上"},
    {"CrlGWtrmOejGseeLLxWKuh", "https://cc.pku.edu.cn/notice/632.html",
     "北大计算中心 2025-11 通告记录的伪装任务名，父目录是 Windows Error Reporting"},
};

// 5) 文件落点。奇安信《2025 银狐木马年度报告》、瑞星、Nextron 都记录过这些路径。
//    这里只列**完整文件名**；`C:\\ProgramData\\` 下任意 .sys 与 IE 目录下的 6 位
//    随机目录由 file_drops.cpp 单独用启发式处理，不塞进这张表。
const NameRule kFilePaths[] = {
    {"C:\\Windows\\Temp\\aceprocted.sys",
     "https://rayblog.rising.com.cn/2026/07/", "瑞星记录的驱动落点"},
    {"C:\\Windows\\Temp\\ranchserv.jpg", "https://rayblog.rising.com.cn/2026/07/",
     "瑞星记录的同目录落点，伪装成图片"},
    {R"(C:\Windows\System32\temp.key)", "https://weishi.360.cn/n/12709.html",
     "奇安信样本分析"},
    {R"(C:\Windows\System32\tmp.key)", "https://weishi.360.cn/n/12709.html", "同上"},
    {R"(C:\Windows\SysWOW64\temp.key)", "https://weishi.360.cn/n/12709.html", "同上"},
    {R"(C:\Windows\SysWOW64\tmp.key)", "https://weishi.360.cn/n/12709.html", "同上"},
    {R"(C:\Program Files\Internet Explorer\temp.key)", "https://weishi.360.cn/n/12709.html",
     "IE 目录被当作白目录用"},
    {R"(C:\Program Files\Internet Explorer\tmp.key)", "https://weishi.360.cn/n/12709.html",
     "同上"},
    {R"(C:\Program Files\Internet Explorer\nvsc.exe)", "https://weishi.360.cn/n/12709.html",
     "本身是驱动，同名文件是落点"},
    {R"(C:\Program Files\Internet Explorer\nvgpu_x64.exe)", "https://weishi.360.cn/n/12709.html",
     "伪装成 NVIDIA 组件"},
    {R"(C:\Program Files\Internet Explorer\nvml.bin)", "https://weishi.360.cn/n/12709.html",
     "伪装成 NVIDIA Machine Learning"},
    {R"(C:\Program Files\Internet Explorer\nvml.dll)", "https://weishi.360.cn/n/12709.html",
     "DLL 侧载"},
    {R"(C:\Program Files\Internet Explorer\glbdll.dll)", "https://weishi.360.cn/n/12709.html",
     "DLL 侧载"},
    {R"(C:\Program Files\Internet Explorer\glbdll.bin)", "https://weishi.360.cn/n/12709.html",
     "同上"},
    {R"(C:\Users\Public\Documents\WindowsData\)",
     "https://www.nextron-systems.com/2025/11/28/thor-vs-silver-fox-uncovering-and-defeating-a-sophisticated-valleyrat-campaign",
     "Nextron 记录攻击者会加一条 deny ACL，让管理员都删不掉"},
};

// 目录：递归扫时只看这些。别全盘走 —— 全盘递归既慢又会产生大量噪音。
struct DirRule {
  const char* dir;
  bool include_subdirs;
  const char* pattern;  // "*" = 全部，否则按文件名后缀匹配
  const char* evidence_url;
  const char* note;
};

const DirRule kFileDropDirs[] = {
    {R"(C:\Windows\Temp)", true, "*", "https://rayblog.rising.com.cn/2026/07/",
     "瑞星记录的落点目录"},
    {R"(C:\Users\Public\Documents\WindowsData)", true, "*",
     "https://www.nextron-systems.com/2025/11/28/thor-vs-silver-fox-uncovering-and-defeating-a-sophisticated-valleyrat-campaign",
     "Nextron 记录该目录下被加了 deny ACL"},
    {R"(C:\ProgramData)", true, ".sys", "https://weishi.360.cn/n/12709.html",
     "奇安信报告：ProgramData 下任意 .sys 都算落点"},
};

// IE 目录下的 6 位随机目录：`C:\Program Files\Internet Explorer\Ab3xY9\`。
// 手动改文件内容会漏，这里做成「恰好 6 位字母数字」的判别式。
const wchar_t* const kIeDirs[] = {
    L"C:\\Program Files\\Internet Explorer",
    L"C:\\Program Files\\Internet Explorer (x86)",
};
const size_t kIeRandomDirLength = 6;

}  // namespace ioc
}  // namespace yh

#endif  // YH_IOC_TABLE_H_
