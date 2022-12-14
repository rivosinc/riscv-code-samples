/*
 * Copyright 2022 Rivos Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _ZVKB_H
#define _ZVKB_H

void zvkb_ghash(uint64_t *X, uint64_t *H);
void zvkb_ghash_init(uint64_t *H);

void zvkg_ghash(uint64_t *Y, const uint64_t *X, uint64_t *H);

#endif	/* _ZVKNS_H */
