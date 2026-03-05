#include "crypto.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <chrono>

// Incluir headers de OpenSSL (más seguro)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

namespace SRDP {

    // ============================================
    // CONSTANTES DE SEGURIDAD
    // ============================================
    const int AES_256_KEY_SIZE = 32;     // 256 bits
    const int AES_BLOCK_SIZE = 16;       // 128 bits
    const int IV_SIZE = 16;               // Vector de inicialización
    const int PBKDF2_ITERATIONS = 100000; // Iteraciones para derivación de clave
    const int TAG_SIZE = 16;              // Tamaño del tag de autenticación (GCM)

    // ============================================
    // IMPLEMENTACIÓN DE CryptoMotor (MEJORADA)
    // ============================================

    CryptoMotor::CryptoMotor(const std::string& clave)
        : version("SRDP Crypto v2.0 - AES-256-GCM") {

        std::cout << "[CRYPTO] Inicializando motor seguro AES-256-GCM..." << std::flush;

        // Inicializar OpenSSL
        OpenSSL_add_all_algorithms();

        cambiarClave(clave);
        std::cout << " [OK]" << std::endl;
    }

    CryptoMotor::~CryptoMotor() {
        std::cout << "[CRYPTO] Limpiando motor de cifrado..." << std::endl;
        limpiarMemoria(clave);

        // Limpiar OpenSSL
        EVP_cleanup();
    }

    std::string CryptoMotor::cifrarTexto(const std::string& textoPlano) {
        if (textoPlano.empty()) {
            return "";
        }

        try {
            // 1. Convertir texto a bytes
            auto bytesPlano = stringABytes(textoPlano);

            // 2. Generar IV aleatorio
            auto iv = generarIV(IV_SIZE);

            // 3. Derivar clave real usando PBKDF2
            std::vector<unsigned char> keyDerivada(AES_256_KEY_SIZE);
            PKCS5_PBKDF2_HMAC(
                reinterpret_cast<const char*>(clave.data()), clave.size(),
                iv.data(), iv.size(),
                PBKDF2_ITERATIONS,
                EVP_sha256(),
                keyDerivada.size(), keyDerivada.data()
            );

            // 4. Configurar cifrado AES-256-GCM
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("No se pudo crear contexto EVP");

            const EVP_CIPHER* cipher = EVP_aes_256_gcm();
            if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error inicializando cifrado");
            }

            // 5. Configurar clave e IV
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                keyDerivada.data(), iv.data()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error configurando clave/IV");
            }

            // 6. Cifrar datos
            std::vector<unsigned char> textoCifrado(bytesPlano.size() + AES_BLOCK_SIZE);
            int outLen = 0, finalLen = 0;

            if (EVP_EncryptUpdate(ctx, textoCifrado.data(), &outLen,
                bytesPlano.data(), bytesPlano.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error durante cifrado");
            }

            int ciphertextLen = outLen;

            if (EVP_EncryptFinal_ex(ctx, textoCifrado.data() + outLen, &finalLen) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error finalizando cifrado");
            }

            ciphertextLen += finalLen;

            // 7. Obtener tag de autenticación (GCM)
            std::vector<unsigned char> tag(TAG_SIZE);
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error obteniendo tag GCM");
            }

            EVP_CIPHER_CTX_free(ctx);

            // 8. Empaquetar: [IV (16) + TAG (16) + DATOS_CIFRADOS]
            std::vector<unsigned char> resultado;
            resultado.reserve(iv.size() + tag.size() + ciphertextLen);
            resultado.insert(resultado.end(), iv.begin(), iv.end());
            resultado.insert(resultado.end(), tag.begin(), tag.end());
            resultado.insert(resultado.end(),
                textoCifrado.begin(),
                textoCifrado.begin() + ciphertextLen);

            // 9. Limpiar memoria sensible
            limpiarMemoria(bytesPlano);
            limpiarMemoria(keyDerivada);

            // 10. Convertir a string para retornar
            std::string resultadoStr = bytesAString(resultado);

            // Codificar a Base64 para texto plano (opcional, pero más seguro)
            // Esto evita problemas con caracteres no imprimibles
            return CryptoUtil::codificarBase64(resultadoStr);

        }
        catch (const std::exception& e) {
            std::cerr << "[CRYPTO] Error en cifrado: " << e.what() << std::endl;
            throw;
        }
    }

    std::string CryptoMotor::descifrarTexto(const std::string& textoCifrado) {
        if (textoCifrado.empty()) {
            return "";
        }

        try {
            // 1. Decodificar de Base64 si es necesario
            std::string datosCifrados;
            try {
                datosCifrados = CryptoUtil::decodificarBase64(textoCifrado);
            }
            catch (...) {
                // Si no es Base64, asumir que es el formato antiguo
                datosCifrados = textoCifrado;
            }

            // 2. Convertir a bytes
            auto bytesCifrados = stringABytes(datosCifrados);

            // Verificar tamaño mínimo (IV + TAG)
            if (bytesCifrados.size() < IV_SIZE + TAG_SIZE) {
                throw std::runtime_error("Datos cifrados corruptos (muy pequeños)");
            }

            // 3. Extraer IV, TAG y datos
            std::vector<unsigned char> iv(
                bytesCifrados.begin(),
                bytesCifrados.begin() + IV_SIZE
            );

            std::vector<unsigned char> tag(
                bytesCifrados.begin() + IV_SIZE,
                bytesCifrados.begin() + IV_SIZE + TAG_SIZE
            );

            std::vector<unsigned char> datosReales(
                bytesCifrados.begin() + IV_SIZE + TAG_SIZE,
                bytesCifrados.end()
            );

            // 4. Derivar clave usando PBKDF2 (mismo proceso que cifrado)
            std::vector<unsigned char> keyDerivada(AES_256_KEY_SIZE);
            PKCS5_PBKDF2_HMAC(
                reinterpret_cast<const char*>(clave.data()), clave.size(),
                iv.data(), iv.size(),
                PBKDF2_ITERATIONS,
                EVP_sha256(),
                keyDerivada.size(), keyDerivada.data()
            );

            // 5. Configurar descifrado AES-256-GCM
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("No se pudo crear contexto EVP");

            const EVP_CIPHER* cipher = EVP_aes_256_gcm();
            if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error inicializando descifrado");
            }

            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                keyDerivada.data(), iv.data()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error configurando clave/IV");
            }

            // 6. Descifrar datos
            std::vector<unsigned char> textoDescifrado(datosReales.size() + AES_BLOCK_SIZE);
            int outLen = 0, finalLen = 0;

            if (EVP_DecryptUpdate(ctx, textoDescifrado.data(), &outLen,
                datosReales.data(), datosReales.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error durante descifrado");
            }

            int plaintextLen = outLen;

            // 7. Configurar tag esperado
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Error configurando tag GCM");
            }

            // 8. Finalizar (verifica autenticidad)
            int ret = EVP_DecryptFinal_ex(ctx, textoDescifrado.data() + outLen, &finalLen);
            EVP_CIPHER_CTX_free(ctx);

            if (ret != 1) {
                throw std::runtime_error("Fallo de autenticación - datos corruptos o clave incorrecta");
            }

            plaintextLen += finalLen;

            // 9. Convertir a string
            std::string resultado = bytesAString(
                std::vector<unsigned char>(
                    textoDescifrado.begin(),
                    textoDescifrado.begin() + plaintextLen
                )
            );

            // 10. Limpiar memoria
            limpiarMemoria(keyDerivada);

            return resultado;

        }
        catch (const std::exception& e) {
            std::cerr << "[CRYPTO] Error en descifrado: " << e.what() << std::endl;
            throw;
        }
    }

    bool CryptoMotor::cifrarArchivo(const std::string& rutaEntrada,
        const std::string& rutaSalida) {
        try {
            std::cout << "[CRYPTO] Cifrando archivo: " << rutaEntrada << std::endl;

            // 1. Leer archivo completo de forma segura
            std::ifstream archivoEntrada(rutaEntrada, std::ios::binary);
            if (!archivoEntrada) {
                std::cerr << "[CRYPTO] Error: No se pudo abrir " << rutaEntrada << std::endl;
                return false;
            }

            // Obtener tamaño
            archivoEntrada.seekg(0, std::ios::end);
            std::streamsize tamano = archivoEntrada.tellg();
            archivoEntrada.seekg(0, std::ios::beg);

            // Leer datos
            std::vector<unsigned char> buffer(tamano);
            if (!archivoEntrada.read(reinterpret_cast<char*>(buffer.data()), tamano)) {
                std::cerr << "[CRYPTO] Error leyendo archivo" << std::endl;
                return false;
            }
            archivoEntrada.close();

            // 2. Convertir a string y cifrar
            std::string textoPlano(buffer.begin(), buffer.end());
            std::string textoCifrado = cifrarTexto(textoPlano);

            // 3. Guardar archivo cifrado
            std::ofstream archivoSalida(rutaSalida, std::ios::binary);
            if (!archivoSalida) {
                std::cerr << "[CRYPTO] Error: No se pudo crear " << rutaSalida << std::endl;
                return false;
            }

            archivoSalida.write(textoCifrado.c_str(), textoCifrado.size());
            archivoSalida.close();

            // 4. Limpiar
            limpiarMemoria(buffer);

            std::cout << "[CRYPTO] Archivo cifrado guardado: " << rutaSalida << std::endl;
            std::cout << "[CRYPTO] Tamaño original: " << tamano << " bytes" << std::endl;
            std::cout << "[CRYPTO] Tamaño cifrado: " << textoCifrado.size() << " bytes" << std::endl;

            return true;

        }
        catch (const std::exception& e) {
            std::cerr << "[CRYPTO] Error cifrando archivo: " << e.what() << std::endl;
            return false;
        }
    }

    bool CryptoMotor::descifrarArchivo(const std::string& rutaEntrada,
        const std::string& rutaSalida) {
        try {
            std::cout << "[CRYPTO] Descifrando archivo: " << rutaEntrada << std::endl;

            // 1. Leer archivo cifrado
            std::ifstream archivoEntrada(rutaEntrada, std::ios::binary);
            if (!archivoEntrada) {
                std::cerr << "[CRYPTO] Error: No se pudo abrir " << rutaEntrada << std::endl;
                return false;
            }

            archivoEntrada.seekg(0, std::ios::end);
            std::streamsize tamano = archivoEntrada.tellg();
            archivoEntrada.seekg(0, std::ios::beg);

            std::vector<unsigned char> buffer(tamano);
            if (!archivoEntrada.read(reinterpret_cast<char*>(buffer.data()), tamano)) {
                std::cerr << "[CRYPTO] Error leyendo archivo cifrado" << std::endl;
                return false;
            }
            archivoEntrada.close();

            // 2. Descifrar
            std::string textoCifrado(buffer.begin(), buffer.end());
            std::string textoDescifrado = descifrarTexto(textoCifrado);

            // 3. Guardar archivo descifrado
            std::ofstream archivoSalida(rutaSalida, std::ios::binary);
            if (!archivoSalida) {
                std::cerr << "[CRYPTO] Error: No se pudo crear " << rutaSalida << std::endl;
                return false;
            }

            archivoSalida.write(textoDescifrado.c_str(), textoDescifrado.size());
            archivoSalida.close();

            std::cout << "[CRYPTO] Archivo descifrado guardado: " << rutaSalida << std::endl;
            return true;

        }
        catch (const std::exception& e) {
            std::cerr << "[CRYPTO] Error descifrando archivo: " << e.what() << std::endl;
            return false;
        }
    }

    void CryptoMotor::cambiarClave(const std::string& nuevaClave) {
        if (nuevaClave.empty()) {
            throw std::invalid_argument("La clave no puede estar vacía");
        }

        std::cout << "[CRYPTO] Derivando nueva clave con PBKDF2..." << std::flush;

        // Limpiar clave anterior
        limpiarMemoria(clave);

        // En lugar de usar la clave directamente, almacenamos un hash
        // para que la clave original no quede en memoria
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, nuevaClave.c_str(), nuevaClave.size());
        SHA256_Final(hash, &sha256);

        // Guardar el hash como "clave" base
        clave.assign(hash, hash + SHA256_DIGEST_LENGTH);

        std::cout << " [OK]" << std::endl;
    }

    std::string CryptoMotor::getVersion() const {
        return version;
    }

    size_t CryptoMotor::getTamanoClave() const {
        return clave.size() * 8; // Devolver en bits
    }

    // ============================================
    // MÉTODOS PRIVADOS (adaptados)
    // ============================================

    std::vector<unsigned char> CryptoMotor::stringABytes(const std::string& str) {
        return std::vector<unsigned char>(str.begin(), str.end());
    }

    std::string CryptoMotor::bytesAString(const std::vector<unsigned char>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }

    std::vector<unsigned char> CryptoMotor::cifrarBytes(
        const std::vector<unsigned char>& bytesPlano) {
        // Este método ya no se usa directamente, se mantiene por compatibilidad
        // pero lanza excepción para forzar uso del nuevo método
        throw std::runtime_error("Usar cifrarTexto() en lugar de cifrarBytes()");
    }

    std::vector<unsigned char> CryptoMotor::descifrarBytes(
        const std::vector<unsigned char>& bytesCifrado) {
        // Este método ya no se usa directamente
        throw std::runtime_error("Usar descifrarTexto() en lugar de descifrarBytes()");
    }

    std::vector<unsigned char> CryptoMotor::generarIV(size_t tamano) {
        std::vector<unsigned char> iv(tamano);

        // Usar RAND_bytes de OpenSSL (criptográficamente seguro)
        if (RAND_bytes(iv.data(), tamano) != 1) {
            // Fallback a random_device si OpenSSL falla
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);

            for (size_t i = 0; i < tamano; ++i) {
                iv[i] = static_cast<unsigned char>(dis(gen));
            }
        }

        return iv;
    }

    void CryptoMotor::limpiarMemoria(std::vector<unsigned char>& datos) {
        if (!datos.empty()) {
            // Sobrescribir con ceros de manera segura (evita optimizaciones)
            volatile unsigned char* ptr = datos.data();
            for (size_t i = 0; i < datos.size(); ++i) {
                ptr[i] = 0;
            }
            datos.clear();
            datos.shrink_to_fit();
        }
    }

    // ============================================
    // IMPLEMENTACIÓN DE CryptoUtil (MEJORADA)
    // ============================================

    std::string CryptoUtil::generarClaveAleatoria(int longitud) {
        if (longitud < 16 || longitud > 128) {
            longitud = 32;  // Por defecto 32 caracteres
        }

        // Usar fuente de entropía fuerte
        std::vector<unsigned char> buffer(longitud);

        if (RAND_bytes(buffer.data(), longitud) == 1) {
            // Convertir a caracteres imprimibles (Base64)
            std::string temp(buffer.begin(), buffer.end());
            return codificarBase64(temp).substr(0, longitud);
        }
        else {
            // Fallback a random_device (menos seguro pero funcional)
            const std::string caracteres =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789"
                "!@#$%^&*()-_=+[]{}|;:,.<>?";

            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, caracteres.size() - 1);

            std::string clave;
            clave.reserve(longitud);

            for (int i = 0; i < longitud; ++i) {
                clave += caracteres[dis(gen)];
            }

            return clave;
        }
    }

    std::string CryptoUtil::calcularHash(const std::string& datos) {
        // Usar SHA-256 real en lugar de hash casero
        unsigned char hash[SHA256_DIGEST_LENGTH];

        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, datos.c_str(), datos.size());
        SHA256_Final(hash, &sha256);

        // Convertir a hexadecimal
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hash[i]);
        }

        return ss.str();
    }

    bool CryptoUtil::verificarIntegridad(const std::string& datos,
        const std::string& hashEsperado) {
        std::string hashCalculado = calcularHash(datos);

        // Comparación en tiempo constante para evitar timing attacks
        if (hashCalculado.length() != hashEsperado.length()) {
            return false;
        }

        volatile int result = 0;
        for (size_t i = 0; i < hashCalculado.length(); ++i) {
            result |= (hashCalculado[i] ^ hashEsperado[i]);
        }

        bool iguales = (result == 0);

        std::cout << "[CRYPTO-UTIL] Verificación integridad: "
            << (iguales ? "✅ PASÓ" : "❌ FALLÓ") << std::endl;

        return iguales;
    }

    std::string CryptoUtil::codificarBase64(const std::string& datos) {
    if (datos.empty()) return "";
    
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, datos.data(), static_cast<int>(datos.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string resultado(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return resultado;
}

std::string CryptoUtil::decodificarBase64(const std::string& base64) {
    if (base64.empty()) return "";
    
    // Calcular tamaño máximo necesario
    int decodeLen = static_cast<int>(base64.size() * 3 / 4);
    std::vector<unsigned char> buffer(decodeLen + 1);
    
    BIO *bio, *b64;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.size()));
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, buffer.data(), decodeLen);
    BIO_free_all(bio);
    
    if (len <= 0) {
        throw std::runtime_error("Error decodificando Base64");
    }
    
    return std::string(reinterpret_cast<char*>(buffer.data()), len);
}

} // namespace SRDP