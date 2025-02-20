<?php

declare(strict_types=1);

namespace Merkeleon\PhpCryptocurrencyAddressValidation\Drivers;

use Merkeleon\PhpCryptocurrencyAddressValidation\Utils\Base64Decoder;

class Base64Crc16Driver extends AbstractDriver
{
    public function match(string $address): bool
    {
        return $this->getPattern($address) === 1;
    }

    public function check(string $address): bool
    {
        try {
            $base64Decode = new Base64Decoder();

            if (!$this->match($address)) {
                return false;
            }

            $decodedData = $base64Decode->urlDecode($address);

            if(!$this->validateLength($decodedData)) {
                return false;
            }

            $addressWithoutCrc = substr($decodedData, 0, 34);

            $providedCrc = bin2hex(substr($decodedData, 34, 2));

            $calculatedCrc = $this->calculateCrc($addressWithoutCrc);

            return $calculatedCrc === $providedCrc;
        } catch (\Exception $e) {
            return false;
        }
    }

    private function validateLength(string $address): bool
    {
        return strlen($address) === 36;
    }

    private function calculateCrc(string $data): string
    {
        $crc = 0;
        $bytes = str_split($data);

        foreach ($bytes as $byte) {
            $crc ^= ord($byte) << 8;

            for ($j = 0; $j < 8; $j++) {
                if ($crc & 0x8000) {
                    $crc = (($crc << 1) ^ 0x1021) & 0xFFFF;
                } else {
                    $crc <<= 1;
                }
                $crc &= 0xFFFF;
            }
        }

        return sprintf('%04x', $crc);
    }

    private function getPattern(string $address): false|int
    {

        return preg_match('/^(UQ|EQ|kQ|0Q|Uf|EF)[A-Za-z0-9\-_]{46}$/', $address);
    }
}
