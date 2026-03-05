// includes/srdp/crypto_simple.h
#ifndef SRDP_CRYPTO_SIMPLE_H
#define SRDP_CRYPTO_SIMPLE_H

#include <string>
#include <vector>

namespace SRDP {

    // ============================================
    // CLASE PRINCIPAL DEL MOTOR DE CIFRADO
    // ============================================
    class CryptoMotor {
    public:
        // ---------- CONSTRUCTORES ----------

        // Constructor con clave personalizada
        CryptoMotor(const std::string& clave);

        // ---------- MÉTODOS PRINCIPALES ----------
        // Cifrar texto
        std::string cifrarTexto(const std::string& textoPlano);

        // Descifrar texto
        std::string descifrarTexto(const std::string& textoCifrado);

        // Cifrar archivo completo
        bool cifrarArchivo(const std::string& rutaEntrada,
            const std::string& rutaSalida);

        // Descifrar archivo completo
        bool descifrarArchivo(const std::string& rutaEntrada,
            const std::string& rutaSalida);

        // ---------- CONFIGURACIÓN ----------
        // Cambiar clave
        void cambiarClave(const std::string& nuevaClave);

        // Obtener información
        std::string getVersion() const;
        size_t getTamanoClave() const;

        // ---------- DESTRUCTOR ----------
        ~CryptoMotor();

    private:
        // ---------- VARIABLES PRIVADAS ----------
        std::vector<unsigned char> clave;  // Clave en bytes
        std::string version;

        // ---------- MÉTODOS PRIVADOS ----------
        // Convertir string a bytes
        std::vector<unsigned char> stringABytes(const std::string& str);

        // Convertir bytes a string
        std::string bytesAString(const std::vector<unsigned char>& bytes);

        // Algoritmo de cifrado simple (XOR mejorado)
        std::vector<unsigned char> cifrarBytes(
            const std::vector<unsigned char>& bytesPlano);

        std::vector<unsigned char> descifrarBytes(
            const std::vector<unsigned char>& bytesCifrado);

        // Generar vector de inicialización (IV)
        std::vector<unsigned char> generarIV(size_t tamano);

        // Limpiar memoria sensible
        void limpiarMemoria(std::vector<unsigned char>& datos);
    };

    // ============================================
    // FUNCIONES UTILITARIAS (estáticas)
    // ============================================
    namespace CryptoUtil {
        // Generar clave aleatoria segura
        std::string generarClaveAleatoria(int longitud = 32);

        // Calcular hash SHA-256 (simplificado)
        std::string calcularHash(const std::string& datos);

        // Verificar integridad
        bool verificarIntegridad(const std::string& datos,
            const std::string& hashEsperado);

        // Codificar base64 (para mostrar claves)
        std::string codificarBase64(const std::string& datos);

        // Decodificar base64
        std::string decodificarBase64(const std::string& base64);
    }

} // namespace SRDP

#endif 
