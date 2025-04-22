/*
 *  (C) Copyright 2022 Password4j (http://password4j.com/).
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

import com.password4j.BadParametersException;
import com.password4j.Hash;
import com.password4j.HashUpdate;
import com.password4j.MessageDigestFunction;
import com.password4j.Password;
import com.password4j.ScryptFunction;


/**
 * In this case the application used MD5 to hash passwords.
 * Here you can see how this dummy DAO verifies the credentials and updates the hash with a stronger algorithm, like scrypt.
 * Note that it already hashes the passwords with scrypt, so it takes in account not only old MD5 hashes but also the new ones with scrypt
 */
public class MigrateFromMD5
{

    public class UserDAO
    {
        /**
         * Hash the password.
         * @param providedPassword password received from the user
         */
        public void storePassword(String providedPassword)
        {
            Hash hash = Password.hash(providedPassword).withScrypt();
            Service.storePasswordInDatabase(hash.getResult());
        }

        /**
         * Verify if the password matches the one saved in the database
         * @param providedPassword password received from the user
         * @return true if mathces, false otherwise
         */
        public boolean verifyCredentials(String providedPassword)
        {
            // Retrieve the password from the Database
            String passwordFromDB = Service.getPasswordFromDatabaseForCurrentUser();

            try
            {
                // Parse the hash and tries to generate a scrypt prototype to use during the verification.
                // If the hash retrieved from the database is not a valid scrypt, a BadParametersException is thrown
                // and that means we found an old MD5 hash.
                ScryptFunction scrypt = ScryptFunction.getInstanceFromHash(passwordFromDB);

                if(Password.check(providedPassword, passwordFromDB).with(scrypt))
                {
                    // The check passed and the user is authenticated
                    return true;
                }
                return false;
            }
            catch (BadParametersException bpe)
            {
                // If scrypt is not recognized it means we are working with a legacy MD5 hash!
                return handleOldPasswords(providedPassword, passwordFromDB);
            }
        }

        /**
         * If mathces, updates the hash with scrypt
         * @param providedPassword password received from the user
         * @param passwordFromDB password saved in the database
         * @return @return true if mathces, false otherwise
         */
        private boolean handleOldPasswords(String providedPassword, String passwordFromDB)
        {
            // Create a MD5 prototype
            MessageDigestFunction md5 = MessageDigestFunction.getInstance("MD5");

            // Check with MD5 and if the check passed it generates a stronger hash with scrypt
            HashUpdate update = Password.check(providedPassword, passwordFromDB).andUpdate().withScrypt(md5);

            // The check passed and the user can be authenticated
            if(update.isVerified())
            {
                // Remember to store the new scrypt hash in the database
                Service.storePasswordInDatabase(update.getHash().getResult());
                return true;
            }
            return false;
        }
    }
}
