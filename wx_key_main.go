package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 定义常量
const (
	ProcessName = "Weixin.exe"
	DllName     = "wx_key.dll"
)

// KeyDumper 结构体
type KeyDumper struct {
	dll *syscall.LazyDLL

	// 内部保存的 DLL 函数指针 (lazy proc)
	// 命名习惯：小写开头，对应 DLL 里的函数
	procInitializeHook   *syscall.LazyProc
	procPollKeyData      *syscall.LazyProc
	procGetStatusMessage *syscall.LazyProc
	procCleanupHook      *syscall.LazyProc
	procGetLastErrorMsg  *syscall.LazyProc

	isHooked bool
}

// 加载 DLL
func NewKeyDumper() (*KeyDumper, error) {
	exePath, _ := os.Executable()
	dllPath := filepath.Join(filepath.Dir(exePath), DllName)

	dll := syscall.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		dll = syscall.NewLazyDLL(DllName)
		if err := dll.Load(); err != nil {
			return nil, fmt.Errorf("无法加载 %s: %v", DllName, err)
		}
	}

	// 绑定 DLL 函数
	// 这里的字符串参数必须和 C++ DLL 的导出名一模一样
	return &KeyDumper{
		dll:                  dll,
		procInitializeHook:   dll.NewProc("InitializeHook"),
		procPollKeyData:      dll.NewProc("PollKeyData"),
		procGetStatusMessage: dll.NewProc("GetStatusMessage"),
		procCleanupHook:      dll.NewProc("CleanupHook"),
		procGetLastErrorMsg:  dll.NewProc("GetLastErrorMsg"),
	}, nil
}

// =========================================================================
// 下面是封装方法，方法名现在与 DLL 导出名严格保持一致
// =========================================================================

// 对应 DLL: InitializeHook
func (kd *KeyDumper) InitializeHook(pid uint32) error {
	ret, _, _ := kd.procInitializeHook.Call(uintptr(pid))
	if ret == 0 {
		errMsg := kd.GetLastErrorMsg()
		return fmt.Errorf("InitializeHook 失败: %s", errMsg)
	}
	kd.isHooked = true
	return nil
}

// 对应 DLL: PollKeyData
func (kd *KeyDumper) PollKeyData() string {
	buf := make([]byte, 128)
	ret, _, _ := kd.procPollKeyData.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	if ret != 0 {
		n := bytes.IndexByte(buf, 0)
		if n == -1 {
			n = len(buf)
		}
		return string(buf[:n])
	}
	return ""
}

// 对应 DLL: GetStatusMessage
// 虽然名字叫 GetStatusMessage，但为了 Go 好用，我们还是返回 (string, int)
func (kd *KeyDumper) GetStatusMessage() (string, int) {
	buf := make([]byte, 512)
	var level int32

	ret, _, _ := kd.procGetStatusMessage.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&level)),
	)

	if ret != 0 {
		n := bytes.IndexByte(buf, 0)
		if n == -1 {
			n = len(buf)
		}
		return string(buf[:n]), int(level)
	}
	return "", -1
}

// 对应 DLL: CleanupHook
func (kd *KeyDumper) CleanupHook() {
	if kd.isHooked {
		fmt.Println("\n[System] 执行 CleanupHook ...")
		kd.procCleanupHook.Call()
		kd.isHooked = false
		fmt.Println("[System] 清理完成。")
	}
}

// 对应 DLL: GetLastErrorMsg
func (kd *KeyDumper) GetLastErrorMsg() string {
	ret, _, _ := kd.procGetLastErrorMsg.Call()
	if ret == 0 {
		return "Unknown error"
	}
	// 处理 char* 返回值
	ptr := unsafe.Pointer(ret)
	buf := make([]byte, 0, 256)
	for {
		b := *(*byte)(ptr)
		if b == 0 {
			break
		}
		buf = append(buf, b)
		ptr = unsafe.Pointer(uintptr(ptr) + 1)
	}
	return string(buf)
}

// 辅助：查找微信 PID
func FindWeChatPID() (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, err
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if name == ProcessName {
			return entry.ProcessID, nil
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return 0, fmt.Errorf("未找到 %s，请先启动微信", ProcessName)
}

func main() {
	log.SetFlags(log.Ltime)

	// 1. 查找 PID
	pid, err := FindWeChatPID()
	if err != nil {
		log.Fatalf("[Error] %v", err)
	}
	log.Printf("[Init] 找到微信进程 PID: %d", pid)

	// 2. 加载 DLL
	dumper, err := NewKeyDumper()
	if err != nil {
		log.Fatalf("[Error] DLL加载失败: %v", err)
	}

	// 3. 监听中断信号 (Ctrl+C)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n[Info] 用户手动中断")
		dumper.CleanupHook()
		os.Exit(0)
	}()

	// 4. 初始化 Hook
	log.Println("[Init] 正在注入 Hook (InitializeHook)...")
	if err := dumper.InitializeHook(pid); err != nil {
		log.Fatalf("[Error] %v", err)
	}
	log.Println("[Success] Hook 初始化成功！请打开微信并点击任意聊天窗口...")

	// 5. 循环轮询
	for {
		// --- 轮询日志 (GetStatusMessage) ---
		for {
			msg, level := dumper.GetStatusMessage()
			if level == -1 {
				break
			}
			prefix := "[INFO]"
			switch level {
			case 1:
				prefix = "[SUCCESS]"
			case 2:
				prefix = "[ERROR]"
			}
			fmt.Printf("%s [DLL] %s\n", prefix, msg)
		}

		// --- 轮询密钥 (PollKeyData) ---
		key := dumper.PollKeyData()
		if key != "" {
			fmt.Println("\n========================================")
			fmt.Println("           捕获到新的密钥")
			fmt.Println("========================================")
			fmt.Printf("Key: %s\n", key)
			fmt.Println("========================================")

			// 拿到 Key 后，按顺序清理并退出
			dumper.CleanupHook()
			fmt.Println("[System] 密钥已保存，程序退出。")
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}

		time.Sleep(100 * time.Millisecond)
	}
}
