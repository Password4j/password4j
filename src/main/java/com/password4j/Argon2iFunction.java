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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class Argon2iFunction implements HashingFunction
{

    private static final int ARGON2_SYNC_POINTS = 4;

    private byte[] output;
    private int outputLength; // -l N
    private double duration;

    private byte[] secret;
    private byte[] additional;

    private int iterations; // -t N
    private int memory; // -m N
    private int lanes; // -p N

    private int version; // -v (10/13)

    private boolean clearMemory = true;
    private Charset charset = StandardCharsets.UTF_8;

    private boolean encodedOnly = false;
    private boolean rawOnly = false;

    public Argon2iFunction()
    {
        this.lanes = 1;
        this.outputLength = 32;
        this.memory = 1 << 12;
        this.iterations = 3;
        this.version = 0x13;
    }



    @Override
    public Hash hash(String plain)
    {
        return null;
    }

    @Override
    public Hash hash(String plain, String salt)
    {
        return null;
    }

    @Override
    public boolean check(String plain, String hashed)
    {
        return false;
    }

    @Override
    public boolean check(String plain, String hashed, String salt)
    {
        return false;
    }

    public void initialize(Instance instance, Argon2 argon2) {
        byte[] initialHash = Functions.initialHash(
                Util.intToLittleEndianBytes(argon2.getLanes()),
                Util.intToLittleEndianBytes(argon2.getOutputLength()),
                Util.intToLittleEndianBytes(argon2.getMemory()),
                Util.intToLittleEndianBytes(argon2.getIterations()),
                Util.intToLittleEndianBytes(argon2.getVersion()),
                Util.intToLittleEndianBytes(argon2.getType().ordinal()),
                Util.intToLittleEndianBytes(argon2.getPasswordLength()),
                argon2.getPassword(),
                Util.intToLittleEndianBytes(argon2.getSaltLength()),
                argon2.getSalt(),
                Util.intToLittleEndianBytes(argon2.getSecretLength()),
                argon2.getSecret(),
                Util.intToLittleEndianBytes(argon2.getAdditionalLength()),
                argon2.getAdditional()
        );
        fillFirstBlocks(instance, initialHash);
    }

    /**
     * (H0 || 0 || i) 72 byte -> 1024 byte
     * (H0 || 1 || i) 72 byte -> 1024 byte
     */
    private void fillFirstBlocks(Instance instance, byte[] initialHash) {

        final byte[] zeroBytes = {0, 0, 0, 0};
        final byte[] oneBytes = {1, 0, 0, 0};

        byte[] initialHashWithZeros = getInitialHashLong(initialHash, zeroBytes);
        byte[] initialHashWithOnes = getInitialHashLong(initialHash, oneBytes);

        for (int i = 0; i < lanes; i++) {

            byte[] iBytes = Util.intToLittleEndianBytes(i);

            System.arraycopy(iBytes, 0, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4, 4);
            System.arraycopy(iBytes, 0, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4, 4);

            byte[] blockhashBytes = Functions.blake2bLong(initialHashWithZeros, ARGON2_BLOCK_SIZE);
            instance.memory[i * instance.getLaneLength() + 0].fromBytes(blockhashBytes);

            blockhashBytes = Functions.blake2bLong(initialHashWithOnes, ARGON2_BLOCK_SIZE);
            instance.memory[i * instance.getLaneLength() + 1].fromBytes(blockhashBytes);
        }
    }

    private static byte[] getInitialHashLong(byte[] initialHash, byte[] appendix) {
        byte[] initialHashLong = new byte[ARGON2_PREHASH_SEED_LENGTH];

        System.arraycopy(initialHash, 0, initialHashLong, 0, ARGON2_PREHASH_DIGEST_LENGTH);
        System.arraycopy(appendix, 0, initialHashLong, ARGON2_PREHASH_DIGEST_LENGTH, 4);

        return initialHashLong;
    }

    private class Instance {

        public Block[] memory;
        private int version;
        private int iterations;
        private int segmentLength;
        private int laneLength;
        private int lanes;


        public Instance(Argon2iFunction argon2) {
            this.version = argon2.version;
            this.iterations = argon2.iterations;
            this.lanes = argon2.lanes;

            /* 2. Align memory size */
            /* Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
            int memoryBlocks = argon2.memory;

            if (memoryBlocks < 2 * ARGON2_SYNC_POINTS * argon2.lanes) {
                memoryBlocks = 2 * ARGON2_SYNC_POINTS * argon2.lanes;
            }

            this.segmentLength = memoryBlocks / (argon2.lanes * ARGON2_SYNC_POINTS);
            this.laneLength = segmentLength * ARGON2_SYNC_POINTS;
            /* Ensure that all segments have equal length */
            memoryBlocks = segmentLength * (argon2.lanes * ARGON2_SYNC_POINTS);

            initMemory(memoryBlocks);
        }

        private void initMemory(int memoryBlocks) {
            this.memory = new Block[memoryBlocks];

            for (int i = 0; i < memory.length; i++) {
                memory[i] = new Block();
            }
        }

        public void clear() {
            for (Block b : memory) {
                b.clear();
            }

            memory = null;
        }

        public Block[] getMemory() {
            return memory;
        }

        public int getVersion() {
            return version;
        }

        public int getIterations() {
            return iterations;
        }

        public int getSegmentLength() {
            return segmentLength;
        }

        public int getLaneLength() {
            return laneLength;
        }

        public int getLanes() {
            return lanes;
        }

        public Argon2Type getType() {
            return type;
        }
}
