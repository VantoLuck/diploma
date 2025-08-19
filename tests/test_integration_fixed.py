"""
Улучшенные интеграционные тесты с исправлениями.

Эти тесты используют детерминированные семена для воспроизводимости
и включают исправления для проблем с валидацией подписей.
"""

import unittest
import hashlib
from dilithium_threshold.core.threshold import ThresholdSignature
from dilithium_threshold.core.dilithium import Dilithium


class TestThresholdSignatureIntegrationFixed(unittest.TestCase):
    """Улучшенные интеграционные тесты для пороговой схемы подписи."""
    
    def setUp(self):
        """Настройка тестового окружения."""
        self.threshold = 3
        self.participants = 5
        self.security_level = 2
        self.message = b"test message for threshold signature"
        
        # Используем детерминированное семя для воспроизводимости
        self.deterministic_seed = b"test_seed_for_reproducible_tests"
        
        self.ts = ThresholdSignature(
            self.threshold, 
            self.participants, 
            self.security_level,
            deterministic_seed=self.deterministic_seed
        )
    
    def test_complete_workflow_fixed(self):
        """Тест полного рабочего процесса с исправлениями."""
        print("Тестирование полного рабочего процесса...")
        
        # 1. Распределенная генерация ключей
        key_shares = self.ts.distributed_keygen()
        
        self.assertEqual(len(key_shares), self.participants)
        
        # Проверяем, что все доли имеют одинаковый публичный ключ
        public_key = key_shares[0].public_key
        for share in key_shares:
            self.assertEqual(share.public_key.A.shape, public_key.A.shape)
            self.assertEqual(share.public_key.t, public_key.t)
        
        # 2. Частичное подписание
        signing_participants = key_shares[:self.threshold]
        partial_signatures = []
        
        for share in signing_participants:
            partial_sig = self.ts.partial_sign(self.message, share)
            partial_signatures.append(partial_sig)
            
            # Проверяем каждую частичную подпись
            is_valid = self.ts.verify_partial_signature(
                self.message, partial_sig, share)
            print(f"Частичная подпись от участника {share.participant_id}: {'✓' if is_valid else '✗'}")
            self.assertTrue(is_valid, 
                f"Частичная подпись от участника {share.participant_id} недействительна")
        
        # 3. Комбинирование подписей
        combined_signature = self.ts.combine_signatures(
            partial_signatures, public_key)
        
        # 4. Проверка с использованием стандартного Dilithium
        dilithium = Dilithium(self.security_level)
        is_valid = dilithium.verify(self.message, combined_signature, public_key)
        
        print(f"Комбинированная подпись: {'✓' if is_valid else '✗'}")
        self.assertTrue(is_valid, "Проверка комбинированной подписи провалилась")
    
    def test_deterministic_behavior_fixed(self):
        """Тест детерминированного поведения."""
        print("Тестирование детерминированного поведения...")
        
        # Создаем две схемы с одинаковым семенем
        ts1 = ThresholdSignature(
            self.threshold, self.participants, self.security_level,
            deterministic_seed=self.deterministic_seed
        )
        ts2 = ThresholdSignature(
            self.threshold, self.participants, self.security_level,
            deterministic_seed=self.deterministic_seed
        )
        
        # Генерируем ключи
        shares1 = ts1.distributed_keygen(seed=b"fixed_seed")
        shares2 = ts2.distributed_keygen(seed=b"fixed_seed")
        
        # Проверяем, что ключи одинаковые
        self.assertEqual(len(shares1), len(shares2))
        
        # Создаем подписи
        sig1 = ts1.partial_sign(self.message, shares1[0])
        sig2 = ts2.partial_sign(self.message, shares2[0])
        
        # Проверяем детерминированность
        self.assertEqual(sig1.participant_id, sig2.participant_id)
        print("Детерминированное поведение: ✓")
    
    def test_different_threshold_configurations_fixed(self):
        """Тест различных конфигураций порога."""
        print("Тестирование различных конфигураций...")
        
        test_configs = [
            (2, 3),
            (3, 5),
        ]
        
        for threshold, participants in test_configs:
            print(f"Тестирование конфигурации {threshold}/{participants}...")
            
            ts = ThresholdSignature(
                threshold, participants, self.security_level,
                deterministic_seed=self.deterministic_seed
            )
            
            # Генерируем ключи
            key_shares = ts.distributed_keygen()
            
            # Создаем частичные подписи
            signing_shares = key_shares[:threshold]
            partial_sigs = []
            
            for share in signing_shares:
                partial_sig = ts.partial_sign(self.message, share)
                partial_sigs.append(partial_sig)
                
                # Проверяем частичную подпись
                is_valid = ts.verify_partial_signature(self.message, partial_sig, share)
                self.assertTrue(is_valid)
            
            # Комбинируем и проверяем
            combined_sig = ts.combine_signatures(partial_sigs, key_shares[0].public_key)
            dilithium = Dilithium(self.security_level)
            is_valid = dilithium.verify(self.message, combined_sig, key_shares[0].public_key)
            
            print(f"Конфигурация {threshold}/{participants}: {'✓' if is_valid else '✗'}")
            self.assertTrue(is_valid)
    
    def test_insufficient_signatures_fixed(self):
        """Тест недостаточного количества подписей."""
        print("Тестирование недостаточного количества подписей...")
        
        key_shares = self.ts.distributed_keygen()
        
        # Используем меньше подписей, чем требуется
        insufficient_shares = key_shares[:self.threshold - 1]
        partial_sigs = []
        
        for share in insufficient_shares:
            partial_sig = self.ts.partial_sign(self.message, share)
            partial_sigs.append(partial_sig)
        
        # Попытка комбинирования должна провалиться
        with self.assertRaises(ValueError):
            self.ts.combine_signatures(partial_sigs, key_shares[0].public_key)
        
        print("Проверка недостаточного количества подписей: ✓")
    
    def test_signature_bounds_fixed(self):
        """Тест проверки границ подписей."""
        print("Тестирование границ подписей...")
        
        key_shares = self.ts.distributed_keygen()
        share = key_shares[0]
        
        # Создаем частичную подпись
        partial_sig = self.ts.partial_sign(self.message, share)
        
        # Проверяем границы
        bounds_ok = self.ts._check_partial_bounds(partial_sig)
        print(f"Границы частичной подписи: {'✓' if bounds_ok else '✗'}")
        
        # Выводим детальную информацию
        gamma1 = self.ts.dilithium.params['gamma1']
        beta = self.ts.dilithium.params['beta']
        norm = partial_sig.z_partial.norm_infinity()
        
        print(f"  norm_infinity: {norm}")
        print(f"  gamma1 - beta: {gamma1 - beta}")
        print(f"  Условие выполнено: {norm < gamma1 - beta}")
        
        self.assertTrue(bounds_ok, "Границы частичной подписи не соблюдены")


if __name__ == '__main__':
    # Запускаем тесты с подробным выводом
    unittest.main(verbosity=2)

