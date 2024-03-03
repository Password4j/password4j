/*
 *  (C) Copyright 2021 Password4j (http://password4j.com/).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package com.password4j.types;

/**
 * Enum containing the different variations of Argon2.
 *
 * @author David Bertoldi
 * @see <a href="https://en.wikipedia.org/wiki/Argon2">Argon2</a>
 * @since 1.5.0
 */
public enum Argon2
{
    /**
     * It maximizes resistance to GPU cracking attacks.
     * It accesses the memory array in a password dependent order, which reduces the possibility of time–memory trade-off (TMTO) attacks,
     * but introduces possible side-channel attacks
     */
    D,

    /**
     * It is optimized to resist side-channel attacks. It accesses the memory array in a password independent order.
     */
    I,

    /**
     * It is a hybrid version. It follows the Argon2i approach for the first half pass over memory and the Argon2d approach for subsequent passes.
     * It is recommended to use Argon2id except when there are reasons to prefer one of the other two modes.
     */
    ID;

}
