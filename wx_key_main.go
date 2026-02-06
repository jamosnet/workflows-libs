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
	DllName     = "wx_key.dll" // 确保 dll 在同级目录或 PATH 中
)

// DLL 封装结构体
type KeyDumper struct {
	dll              *syscall.LazyDLL
	initializeHook   *syscall.LazyProc
	pollKeyData      *syscall.LazyProc
	getStatusMessage *syscall.LazyProc
	cleanupHook      *syscall.LazyProc
	getLastErrorMsg  *syscall.LazyProc
	isHooked         bool
}

// 加载 DLL
func NewKeyDumper() (*KeyDumper, error) {
	// 获取当前路径，确保能找到 dll
	exePath, _ := os.Executable()
	dllPath := filepath.Join(filepath.Dir(exePath), DllName)
	
	// 也可以直接加载，取决于你的环境
	dll := syscall.NewLazyDLL(dllPath) 
	if err := dll.Load(); err != nil {
		// 尝试直接加载文件名（如果还在系统路径里）
		dll = syscall.NewLazyDLL(DllName)
		if err := dll.Load(); err != nil {
			return nil, fmt.Errorf("无法加载 %s: %v", DllName, err)
		}
	}

	return &KeyDumper{
		dll:              dll,
		initializeHook:   dll.NewProc("InitializeHook"),
		pollKeyData:      dll.NewProc("PollKeyData"),
		getStatusMessage: dll.NewProc("GetStatusMessage"),
		cleanupHook:      dll.NewProc("CleanupHook"),
		getLastErrorMsg:  dll.NewProc("GetLastErrorMsg"),
	}, nil
}

// 1. 初始化 Hook
func (kd *KeyDumper) Initialize(pid uint32) error {
	ret, _, _ := kd.initializeHook.Call(uintptr(pid))
	if ret == 0 { // 返回 false
		errMsg := kd.GetLastError()
		return fmt.Errorf("初始化失败: %s", errMsg)
	}
	kd.isHooked = true
	return nil
}

// 2. 轮询密钥
func (kd *KeyDumper) PollKey() string {
	// 指南建议缓冲区 >= 65，我们给 128 安全点
	buf := make([]byte, 128)
	ret, _, _ := kd.pollKeyData.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	if ret != 0 { // 返回 true
		// 转换 C string 到 Go string
		n := bytes.IndexByte(buf, 0)
		if n == -1 {
			n = len(buf)
		}
		return string(buf[:n])
	}
	return ""
}

// 3. 获取日志
func (kd *KeyDumper) GetLog() (string, int) {
	buf := make([]byte, 512)
	var level int32

	ret, _, _ := kd.getStatusMessage.Call(
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

// 4. 清理 Hook (至关重要)
func (kd *KeyDumper) Cleanup() {
	if kd.isHooked {
		fmt.Println("\n[System] 正在清理 Hook 痕迹...")
		kd.cleanupHook.Call()
		kd.isHooked = false
		fmt.Println("[System] 清理完成，安全退出。")
	}
}

// 辅助：获取错误信息 (char* 转 string)
func (kd *KeyDumper) GetLastError() string {
	ret, _, _ := kd.getLastErrorMsg.Call()
	if ret == 0 {
		return "Unknown error"
	}
	// 读取内存中的 C 字符串
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

	// 3. 监听中断信号 (Ctrl+C)，确保清理
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		dumper.Cleanup()
		os.Exit(0)
	}()

	// 4. 初始化 Hook
	log.Println("[Init] 正在注入 Hook...")
	if err := dumper.Initialize(pid); err != nil {
		log.Fatalf("[Error] %v", err)
	}
	log.Println("[Success] Hook 初始化成功！请打开微信并点击聊天窗口...")

	// 5. 循环轮询
	foundKeys := make(map[string]bool)
	
	for {
		// --- 轮询日志 ---
		for {
			msg, level := dumper.GetLog()
			if level == -1 {
				break // 没有日志了
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

		// --- 轮询密钥 ---
		key := dumper.PollKey()
		if key != "" {
			if !foundKeys[key] {
				foundKeys[key] = true
				fmt.Println("\n========================================")
				fmt.Println("           捕获到新的密钥")
				fmt.Println("========================================")
				fmt.Printf("Key: %s\n", key)
				fmt.Println("========================================")
				
				// 注意：这里我不主动退出，因为可能还有图片Key或其他Key
				// 如果你想拿一个就跑，可以在这里调用 dumper.Cleanup() 然后 break
			}
		}

		time.Sleep(100 * time.Millisecond)
	}
}
