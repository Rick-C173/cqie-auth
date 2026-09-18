//
// compat.h - POSIX / Winsock 平台差异集中层
//
// 原则：网络（socket 类型/收发/非阻塞/错误码）、时间（单调钟/墙上钟）、
// 睡眠、原子替换这几类差异只在这里出现；其余源文件只 include 本头文件，
// 不再直接碰 <sys/socket.h> / <winsock2.h>。
//
#ifndef COMPAT_H
#define COMPAT_H

#ifdef _WIN32

  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0601 /* GetTickCount64 / WSAPoll / inet_ntop 需要 Vista+ */
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>

  typedef SOCKET sock_t;
  typedef unsigned long nfds_t; /* WSAPoll 的个数参数类型（POSIX 叫 nfds_t） */
  #define SOCK_INVALID   INVALID_SOCKET
  #define sock_close     closesocket
  #define sock_errno     WSAGetLastError()
  #define poll           WSAPoll
  #define strncasecmp    _strnicmp

  /* 非阻塞 connect 未完成时 Winsock 报 WSAEWOULDBLOCK（POSIX 是 EINPROGRESS）；
   * 非阻塞 send/recv 暂无数据时两者都报 WSAEWOULDBLOCK / EWOULDBLOCK */
  #define SOCK_ERR_INPROGRESS WSAEWOULDBLOCK
  #define SOCK_ERR_WOULDBLOCK WSAEWOULDBLOCK
  #define SOCK_ERR_INTR       WSAEINTR

  int sock_init(void); /* WSAStartup（幂等），成功返回 1 */
  void sock_quit(void);

#else

  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <arpa/inet.h>
  #include <strings.h> /* strncasecmp */
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <unistd.h>

  typedef int sock_t;
  #define SOCK_INVALID   (-1)
  #define sock_close     close
  #define sock_errno     errno
  #define sock_init()    1
  #define sock_quit()    ((void)0)

  #define SOCK_ERR_INPROGRESS EINPROGRESS
  #define SOCK_ERR_WOULDBLOCK EWOULDBLOCK
  #define SOCK_ERR_INTR       EINTR

#endif

/*
 * 取非阻塞 connect 的连接结果（SO_ERROR），失败返回 -1。
 * 封装掉 POSIX( socklen_t* / void* ) 与 Winsock( int* / char* ) 的签名差异。
 */
int sock_take_error(sock_t fd);

/* 非阻塞开关：on=1 开 / 0 恢复阻塞。成功返回 0，失败 -1 */
int sock_nonblock(sock_t fd, int on);

/* 单调时钟，毫秒（程序启动后单调递增，用于超时/耗时） */
long long compat_mono_ms(void);

/* 墙上钟的 时:分:秒.毫秒（日志前缀用） */
void compat_localtime(int* hour, int* min, int* sec, int* msec);

/* 毫秒睡眠 */
void compat_msleep(int ms);

/* 建目录（POSIX mkdir(path, 0700) / Windows _mkdir(path)，权限在 Windows 无意义） */
int compat_mkdir(const char* path);

/*
 * 把控制台输入/输出码页切到 UTF-8（程序内字符串是 UTF-8）。
 * POSIX 下是空操作。Windows 每次运行设置即可，不必恢复。
 */
void compat_console_utf8(void);

/*
 * 终端交互辅助（首次运行向导用）。
 * compat_stdin_is_tty：stdin 是否为终端——cron/管道下为 0，向导不应触发。
 * compat_echo：开关终端回显（密码输入）；非终端或失败时静默无害。
 */
int compat_stdin_is_tty(void);
void compat_echo(int on);

#endif /* COMPAT_H */
