/*
 *  (C) Copyright 2020 Password4j (http://password4j.com/).
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
package com.password4j;

public class BenchmarkResult<P extends AbstractHashingFunction>
{

    private final P prototype;

    private final long elapsed;

    BenchmarkResult(P prototype, long elapsed)
    {
        this.prototype = prototype;
        this.elapsed = elapsed;
    }

    public P getPrototype()
    {
        return prototype;
    }

    public long getElapsed()
    {
        return elapsed;
    }
}
