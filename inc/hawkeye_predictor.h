// Hawkeye Cache 

#ifndef PREDICTOR_H
#define PREDICTOR_H

using namespace std;

#include <iostream>

#include <map>
#include <math.h>
#include <set>
#include <vector>

// 表示地址信息的结构体
struct ADDR_INFO {
  uint64_t addr;        // 地址
  uint32_t last_quanta; // 上一次访问的时间步
  uint64_t PC;          // 程序计数器
  bool prefetched;      // 是否是预取
  uint32_t lru;         // 最近最少使用（LRU）计数

  // 初始化地址信息
  void init(unsigned int curr_quanta) {
    last_quanta = 0;
    PC = 0;
    prefetched = false;
    lru = 0;
  }

  // 更新地址信息
  void update(unsigned int curr_quanta, uint64_t _pc, bool prediction) {
    last_quanta = curr_quanta;
    PC = _pc;
  }

  // 标记为预取
  void mark_prefetch() { prefetched = true; }
};


// 表示OPTgen的结构体，用于缓存替换策略中的优化器
struct OPTgen {
  vector<unsigned int> liveness_history; // 活跃度历史记录

  uint64_t num_cache;     // 缓存命中次数
  uint64_t num_dont_cache; // 不缓存次数
  uint64_t access;         // 访问次数

  uint64_t CACHE_SIZE; // 缓存大小

  // 初始化函数
  void init(uint64_t size) {
    num_cache = 0;
    num_dont_cache = 0;
    access = 0;
    CACHE_SIZE = size;
    liveness_history.resize(OPTGEN_VECTOR_SIZE, 0);
  }

  // 增加一次访问记录
  void add_access(uint64_t curr_quanta) {
    access++;
    liveness_history[curr_quanta] = 0;
  }

  // 增加一次预取记录
  void add_prefetch(uint64_t curr_quanta) { liveness_history[curr_quanta] = 0; }

  // 判断是否应该进行缓存
  bool should_cache(uint64_t curr_quanta, uint64_t last_quanta) {
    bool is_cache = true;

    unsigned int i = last_quanta;
    while (i != curr_quanta) {
      // 如果活跃度超过缓存大小，则不进行缓存
      if (liveness_history[i] >= CACHE_SIZE) {
        is_cache = false;
        break;
      }

      i = (i + 1) % liveness_history.size();
    }

    // 如果应该进行缓存，则更新活跃度历史记录
    if ((is_cache)) {
      i = last_quanta;
      while (i != curr_quanta) {
        liveness_history[i]++;
        i = (i + 1) % liveness_history.size();
      }
      assert(i == curr_quanta);
    }

    // 根据结果更新缓存命中次数和不缓存次数
    if (is_cache)
      num_cache++;
    else
      num_dont_cache++;

    return is_cache;
  }

  // 获取OPTgen的缓存命中次数
  uint64_t get_num_opt_hits() {
    return num_cache;

    // 以下代码不会被执行，因为前面已经返回了结果
    uint64_t num_opt_misses = access - num_cache;
    return num_opt_misses;
  }
};


// 计算CRC校验
uint64_t CRC(uint64_t _blockAddress) {
  static const unsigned long long crcPolynomial = 3988292384ULL;
  unsigned long long _returnVal = _blockAddress;
  for (unsigned int i = 0; i < 32; i++)
    _returnVal = ((_returnVal & 1) == 1) ? ((_returnVal >> 1) ^ crcPolynomial)
                                         : (_returnVal >> 1);
  return _returnVal;
}

// Hawkeye的PC预测器类
class HAWKEYE_PC_PREDICTOR {
  map<uint64_t, short unsigned int> SHCT; // Signature History Count Table

public:
  // 增加PC的预测计数
  void increment(uint64_t pc) {
    uint64_t signature = CRC(pc) % SHCT_SIZE;
    if (SHCT.find(signature) == SHCT.end())
      SHCT[signature] = (1 + MAX_SHCT) / 2;

    SHCT[signature] =
        (SHCT[signature] < MAX_SHCT) ? (SHCT[signature] + 1) : MAX_SHCT;
  }

  // 减小PC的预测计数
  void decrement(uint64_t pc) {
    uint64_t signature = CRC(pc) % SHCT_SIZE;
    if (SHCT.find(signature) == SHCT.end())
      SHCT[signature] = (1 + MAX_SHCT) / 2;
    if (SHCT[signature] != 0)
      SHCT[signature] = SHCT[signature] - 1;
  }

  // 获取PC的预测结果
  bool get_prediction(uint64_t pc) {
    uint64_t signature = CRC(pc) % SHCT_SIZE;
    if (SHCT.find(signature) != SHCT.end() &&
        SHCT[signature] < ((MAX_SHCT + 1) / 2))
      return false;
    return true;
  }
};


#endif