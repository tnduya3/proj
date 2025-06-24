from django.core.management.base import BaseCommand
from video_app.security_utils import generate_secure_jwt_secret, validate_jwt_secret_strength
import os

class Command(BaseCommand):
    help = 'Generate secure JWT secret keys for production use'

    def add_arguments(self, parser):
        parser.add_argument(
            '--validate',
            type=str,
            help='Validate the strength of an existing JWT secret key',
        )
        parser.add_argument(
            '--export',
            action='store_true',
            help='Generate export command for environment variable',
        )

    def handle(self, *args, **options):
        if options['validate']:
            # Validate an existing key
            secret_key = options['validate']
            is_valid, message = validate_jwt_secret_strength(secret_key)
            
            if is_valid:
                self.stdout.write(
                    self.style.SUCCESS(f'✅ {message}')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'❌ {message}')
                )
            return

        # Generate a new secure JWT secret
        new_secret = generate_secure_jwt_secret()
        
        self.stdout.write('\n' + '='*60)
        self.stdout.write(
            self.style.SUCCESS('🔐 SECURE JWT SECRET KEY GENERATED')
        )
        self.stdout.write('='*60)
        
        self.stdout.write(f'\nGenerated JWT Secret Key:')
        self.stdout.write(f'{new_secret}')
        
        self.stdout.write(f'\nKey Length: {len(new_secret)} characters')
        self.stdout.write(f'Entropy: ~{len(new_secret) * 6} bits')
        
        if options['export']:
            self.stdout.write('\n' + '-'*60)
            self.stdout.write('ENVIRONMENT VARIABLE EXPORT COMMANDS:')
            self.stdout.write('-'*60)
            self.stdout.write('\n📋 For Windows (Command Prompt):')
            self.stdout.write(f'set JWT_SECRET_KEY={new_secret}')
            
            self.stdout.write('\n📋 For Windows (PowerShell):')
            self.stdout.write(f'$env:JWT_SECRET_KEY="{new_secret}"')
            
            self.stdout.write('\n📋 For Linux/Mac (Bash):')
            self.stdout.write(f'export JWT_SECRET_KEY="{new_secret}"')
            
            self.stdout.write('\n📋 For .env file:')
            self.stdout.write(f'JWT_SECRET_KEY={new_secret}')
        
        self.stdout.write('\n' + '-'*60)
        self.stdout.write('🛡️  SECURITY RECOMMENDATIONS:')
        self.stdout.write('-'*60)
        self.stdout.write('1. Store this key securely (never commit to version control)')
        self.stdout.write('2. Use environment variables in production')
        self.stdout.write('3. Rotate keys periodically for enhanced security')
        self.stdout.write('4. Use different keys for different environments')
        self.stdout.write('5. Consider using a secure key management service')
        
        self.stdout.write('\n' + '='*60)
        
        # Validate the generated key
        is_valid, message = validate_jwt_secret_strength(new_secret)
        if is_valid:
            self.stdout.write(
                self.style.SUCCESS(f'✅ Validation: {message}')
            )
        else:
            self.stdout.write(
                self.style.ERROR(f'❌ Validation: {message}')
            )
