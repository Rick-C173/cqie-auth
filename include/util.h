//
// util.h - 字符串 / 文件小工具
//
#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

/* 等效 JS encodeURIComponent，返回 malloc 的字符串（失败返回 NULL） */
char* urlencode(const char* s);

/* 从 JSON 文本中取 "field":"value"，成功返回 1（字段名假定唯一，与接口一致） */
int extract_field(const char* page, const char* field, char* out, size_t outsz);

/* 在 <option value="xxx">名称</option> 中按名称匹配取 value，成功返回 1 */
int extract_service(const char* page, const char* name, char* out, size_t outsz);

/* 从认证页 JS 中提取 location.href='...'，找不到返回 NULL（malloc） */
char* fetch_redirect_url(const char* page);

/* 从 queryString 中提取 mac 参数值（取最后一次出现），成功返回 1 */
int extract_mac(const char* query_string, char* out, size_t outsz);

/* 从 queryString（a=1&b=2 形态）里取 name 参数值，取最后一次出现，
 * 兼容 name 位于串首（无前置 &）；成功返回 1 */
int extract_qs_param(const char* qs, const char* name, char* out, size_t outsz);


/*
 * 等效 `xxd -r -p`：跳过空白、遇其它非十六进制字符即停，两两拼成字节。
 * hex_decode 写入 out（不做 \0 结尾语义上的保证外处理），返回解码出的字节数；
 * hex_print_decode 把结果写到 stdout 并补换行。
 */
size_t hex_decode(const char* s, char* out, size_t outsz);
void hex_print_decode(const char* s);

/* 读文件并去除首尾空白，成功返回 1（等效 shell 的 $(cat file)） */
int file_read_trim(const char* path, char* out, size_t outsz);

/* 睡眠 ms 毫秒 */
void msleep(int ms);

#endif /* UTIL_H */
