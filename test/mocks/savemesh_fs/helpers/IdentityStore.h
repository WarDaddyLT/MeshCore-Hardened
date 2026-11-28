#pragma once

// In-memory filesystem for native preference and managed-policy tests.

#include <Arduino.h>
#include <Identity.h>
#include <map>
#include <string>
#include <utility>

struct MockFile : public Stream {
  std::string* data = nullptr;
  size_t pos = 0;
  bool* fail_writes = nullptr;

  explicit operator bool() const { return data != nullptr; }
  size_t size() const { return data ? data->size() : 0; }
  int available() override { return data ? (int)(data->size() - pos) : 0; }
  int read() override { return (data && pos < data->size()) ? (unsigned char)(*data)[pos++] : -1; }
  size_t read(uint8_t* buffer, size_t length) { return readBytes(buffer, length); }
  int peek() override { return (data && pos < data->size()) ? (unsigned char)(*data)[pos] : -1; }
  size_t write(uint8_t b) override {
    if (!data || (fail_writes && *fail_writes)) return 0;
    data->push_back((char)b);
    return 1;
  }
  size_t print(unsigned char v, int r = DEC) override { return Print::print(std::to_string(v).c_str()); }
  size_t print(int v, int r = DEC) override { return Print::print(std::to_string(v).c_str()); }
  size_t print(unsigned int v, int r = DEC) override { return Print::print(std::to_string(v).c_str()); }
  size_t print(long v, int r = DEC) override { return Print::print(std::to_string(v).c_str()); }
  size_t print(unsigned long v, int r = DEC) override { return Print::print(std::to_string(v).c_str()); }
  using Print::print;
  using Print::write;
  void close() {}
};

struct MockFS {
  std::map<std::string, std::string> files;
  bool fail_writes = false;   // simulates a full or failing filesystem
  bool fail_rename = false;

  bool exists(const char* name) { return files.count(name) > 0; }
  MockFile open(const char* name) {
    MockFile f;
    auto it = files.find(name);
    if (it != files.end()) f.data = &it->second;
    return f;
  }
  MockFile open(const char* name, const char*, bool) {
    MockFile f;
    files[name].clear();
    f.data = &files[name];
    f.fail_writes = &fail_writes;
    return f;
  }
  bool remove(const char* name) { return files.erase(name) > 0; }
  bool rename(const char* from, const char* to) {
    if (fail_rename || !exists(from) || exists(to)) return false;
    files[to] = std::move(files.at(from));
    files.erase(from);
    return true;
  }
};

using File = MockFile;
#define FILESYSTEM MockFS
