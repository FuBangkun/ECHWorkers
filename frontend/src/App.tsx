import { createSignal, onMount, onCleanup } from "solid-js";
import { StartWorker, StopWorker, SetSystemProxy } from "../bindings/changeme/workerservice";
import { Events } from "@wailsio/runtime";

interface AppConfig {
  server?: string;
  listen?: string;
  token?: string;
  ip?: string;
  dns?: string;
  ech?: string;
  routingMode?: string;
}

function App() {
  const [server, setServer] = createSignal<string>("");
  const [listenAddr, setListenAddr] = createSignal<string>("127.0.0.1:30000");
  const [token, setToken] = createSignal<string>("");
  const [ip, setIp] = createSignal<string>("saas.sin.fan");
  const [dns, setDns] = createSignal<string>("dns.alidns.com/dns-query");
  const [ech, setEch] = createSignal<string>("cloudflare-ech.com");
  const [routingMode, setRoutingMode] = createSignal<string>("bypass_cn");

  const [isRunning, setIsRunning] = createSignal<boolean>(false);
  const [systemProxyEnabled, setSystemProxyEnabled] = createSignal<boolean>(false);
  const [logOutput, setLogOutput] = createSignal<string>("");

  let logRef: HTMLDivElement | undefined;

  const appendLog = (msg: string) => {
    setLogOutput((prev) => prev + msg);
    if (logRef) {
      logRef.scrollTop = logRef.scrollHeight;
    }
  };

  const toggleProxy = async (enable: boolean) => {
    try {
      const errMsg = await SetSystemProxy(
        enable,
        listenAddr(),
        routingMode()
      );
      if (errMsg) {
        appendLog(`[系统] 代理设置失败: ${errMsg}\n`);
        return;
      }
      setSystemProxyEnabled(enable);
      appendLog(`[系统] ${enable ? "已设置" : "已关闭"}系统代理\n`);
    } catch (e) {
      appendLog(`[系统] 代理设置请求失败: ${e}\n`);
    }
  };

  const executeStart = async () => {
    if (!server()) {
      alert("请输入服务地址");
      return;
    }
    saveConfig();
    try {
      const errMsg = await StartWorker(
        server(),
        listenAddr(),
        token(),
        ip(),
        dns(),
        ech(),
        routingMode()
      );

      if (errMsg) {
        appendLog(`[系统] 启动失败: ${errMsg}\n`);
        return;
      }

      setIsRunning(true);
      appendLog(`[系统] 已启动代理服务器\n`);

      await toggleProxy(true);
    } catch (e) {
      appendLog(`[系统] 启动请求失败: ${e}\n`);
    }
  };

  onMount(() => {
    const saved = localStorage.getItem("ech_workers_config");
    if (saved) {
      try {
        const config: AppConfig = JSON.parse(saved);
        if (config.server) setServer(config.server);
        if (config.listen) setListenAddr(config.listen);
        if (config.token) setToken(config.token);
        if (config.ip) setIp(config.ip);
        if (config.dns) setDns(config.dns);
        if (config.ech) setEch(config.ech);
        if (config.routingMode) setRoutingMode(config.routingMode);
      } catch (e) {
        console.error("加载缓存配置失败", e);
      }
    }

    const unlistenTrayRequest = Events.On("tray-request-start", () => {
      executeStart();
    });

    const unlistenLog = Events.On("log-output", (event) => {
      if (event && event.data) {
        appendLog(event.data);
      } else if (typeof event === "string") {
        appendLog(event);
      }
    });

    const unlistenFinished = Events.On("process-finished", () => {
      appendLog("[系统] 进程已停止。\n");
      setIsRunning(false);
      if (systemProxyEnabled()) {
        toggleProxy(false);
      }
    });

    onCleanup(() => {
      if (unlistenTrayRequest) unlistenTrayRequest();
      if (unlistenLog) unlistenLog();
      if (unlistenFinished) unlistenFinished();
    });
  });

  const saveConfig = () => {
    const config: AppConfig = {
      server: server(),
      listen: listenAddr(),
      token: token(),
      ip: ip(),
      dns: dns(),
      ech: ech(),
      routingMode: routingMode(),
    };
    localStorage.setItem("ech_workers_config", JSON.stringify(config));
  };

  return (
    <div class="max-w-4xl mx-auto p-6 bg-slate-50 min-h-screen text-slate-800 font-sans antialiased">
      <section class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm mb-5">
        <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4">控制面板</h2>
        <div class="flex flex-wrap gap-3">
          <button
            class={`px-4 py-2 text-white rounded-lg text-sm font-medium transition-colors shadow-sm ${isRunning() ? "bg-rose-600 hover:bg-rose-700" : "bg-blue-600 hover:bg-blue-700"
              }`}
            onClick={async () => {
              if (isRunning()) {
                try {
                  await StopWorker();
                } catch (e) {
                  appendLog(`[系统] 停止请求失败: ${e}\n`);
                }
              } else {
                await executeStart();
              }
            }}
          >
            {isRunning() ? "停止代理" : "启动代理"}
          </button>
          <button
            class="px-4 py-2 bg-white text-slate-500 border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
            onClick={() => setLogOutput("")}
          >
            清空日志
          </button>
        </div>
      </section>

      <section class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm mb-5">
        <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-3">运行日志</h2>
        <div
          ref={logRef}
          class="w-full h-52 p-3 box-border bg-slate-900 text-slate-200 font-mono text-xs rounded-lg overflow-y-auto overflow-x-hidden whitespace-pre-wrap break-all leading-relaxed shadow-inner"
        >
          {logOutput() || <span class="text-slate-500 italic">暂无运行日志...</span>}
        </div>
      </section>

      <section class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm mb-5">
        <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4">代理配置</h2>
        <div class="space-y-4">
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <label class="sm:w-32 text-sm font-medium text-slate-600">服务地址:</label>
            <input
              type="text"
              class="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-blue-500 focus:bg-white transition-all disabled:opacity-60 disabled:cursor-not-allowed"
              placeholder="例如: your-worker.workers.dev:443"
              value={server()}
              onInput={(e) => setServer(e.currentTarget.value)}
              disabled={isRunning()}
            />
          </div>
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <label class="sm:w-32 text-sm font-medium text-slate-600">监听地址:</label>
            <input
              type="text"
              class="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-blue-500 focus:bg-white transition-all disabled:opacity-60 disabled:cursor-not-allowed"
              placeholder="例如: 127.0.0.1:30000"
              value={listenAddr()}
              onInput={(e) => setListenAddr(e.currentTarget.value)}
              disabled={isRunning()}
            />
          </div>
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <label class="sm:w-32 text-sm font-medium text-slate-600">身份令牌:</label>
            <input
              type="password"
              class="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-blue-500 focus:bg-white transition-all"
              placeholder="身份验证令牌（可选）"
              value={token()}
              onInput={(e) => setToken(e.currentTarget.value)}
            />
          </div>
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <label class="sm:w-32 text-sm font-medium text-slate-600">优选IP或域名:</label>
            <input
              type="text"
              class="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-blue-500 focus:bg-white transition-all"
              value={ip()}
              onInput={(e) => setIp(e.currentTarget.value)}
            />
          </div>
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <label class="sm:w-32 text-sm font-medium text-slate-600">DOH服务器:</label>
            <input
              type="text"
              class="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-blue-500 focus:bg-white transition-all"
              value={dns()}
              onInput={(e) => setDns(e.currentTarget.value)}
            />
          </div>
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <label class="sm:w-32 text-sm font-medium text-slate-600">ECH域名:</label>
            <input
              type="text"
              class="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-blue-500 focus:bg-white transition-all"
              value={ech()}
              onInput={(e) => setEch(e.currentTarget.value)}
            />
          </div>
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <label class="sm:w-32 text-sm font-medium text-slate-600">代理模式:</label>
            <select
              class="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-blue-500 focus:bg-white transition-all"
              value={routingMode()}
              onChange={(e) => setRoutingMode(e.currentTarget.value)}
            >
              <option value="global">全局代理</option>
              <option value="bypass_cn">跳过中国大陆</option>
            </select>
          </div>
        </div>
      </section>
    </div>
  );
}

export default App;