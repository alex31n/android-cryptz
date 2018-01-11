# android-cryptz
A simple AES encryption library for android 
 &nbsp;
 
 **Defaults encryption:**
 * 128-bit AES key
 * CBC mode
 * PKCS7Padding
 * 0000000000000000 IV*
 
 &nbsp;
 &nbsp;
 
 
### Installation

#### Gradle 

```
dependencies {
        compile 'com.ornach.andlibs:android-cryptz:1.0'
}
```

&nbsp;
#### Maven

```
<dependency>
    <groupId>com.ornach.andlibs</groupId>    
    <artifactId>android-cryptz</artifactId>
    <version>1.0</version>
    <type>pom</type> 
</dependency>
```

&nbsp;

### Basic usage
```
String key="1234567890123456";
String text = "This is simple text";

try {

	String encryptText = AesEncryption.encrypt(key, text);
	String decryptText = AesEncryption.decrypt(key, encryptText);
	
} catch (GeneralSecurityException e) {
	// An error founds
}
```
&nbsp;
### Disclaimer
Before use this library in to project please check everything as you need. I am not taking liability if unwanted situation occur.

&nbsp;
&nbsp;
## License
    Copyright 2017 Alex Beshine
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and limitations under the License.
