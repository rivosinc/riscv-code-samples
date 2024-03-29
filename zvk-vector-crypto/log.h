// Copyright 2023 Rivos Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef LOG_H_
#define LOG_H_

#define LOG(...) test_log(__VA_ARGS__);

__attribute__((__format__ (__printf__, 1, 2)))
extern void test_log(const char* fmt, ...);

#endif  // LOG_H_
