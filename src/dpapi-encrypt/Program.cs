using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IntelligentPlant.DpapiEncrypt {
    internal class Program {

        static async Task<int> Main(string[] args) {
            var rootCommand = new RootCommand();
            rootCommand.AddCommand(GetEncryptCommand());
            rootCommand.AddCommand(GetDecryptCommand());

            return await rootCommand.InvokeAsync(args).ConfigureAwait(false);
        }


        private static Command GetEncryptCommand() {
            var command = new Command(
                "encrypt",
                "Encrypts data using the Windows DPAPI"
            );
            command.Argument.AddValidator(x => {
                var valueArg = x.Children["value"];
                if (valueArg?.Arguments?.FirstOrDefault() == null) {
                    return "A value is required.";
                }

                return null;
            });

            var opt = new Option(
                "--scope",
                $"Specifies the DPAPI scope ({DataProtectionScope.CurrentUser}, {DataProtectionScope.LocalMachine}).",
                new Argument<DataProtectionScope>(DataProtectionScope.CurrentUser)
            );
            command.AddOption(opt);

            opt = new Option(
                "--entropy",
                "A base64-encoded byte array containing additional entropy to use when encrypting the data.",
                new Argument<string>(string.Empty)
            );
            command.AddOption(opt);

            opt = new Option(
                "--value",
                "The value to encrypt.",
                new Argument<string>()
            );
            command.AddOption(opt);

            command.Handler = CommandHandler.Create(typeof(Program).GetMethod(nameof(Encrypt), System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic));
            return command;
        }


        private static Command GetDecryptCommand() {
            var command = new Command(
                "decrypt",
                "Decrypts data that was encrypted using the Windows DPAPI"
            );
            command.Argument.AddValidator(x => {
                var valueArg = x.Children["value"];
                if (valueArg?.Arguments?.FirstOrDefault() == null) {
                    return "A value is required.";
                }

                return null;
            });

            var opt = new Option(
                "--entropy",
                "A base64-encoded byte array containing additional entropy that was used to encrypt the data.",
                new Argument<string>(string.Empty)
            );
            command.AddOption(opt);

            opt = new Option(
                "--value",
                "The value to decrypt.",
                new Argument<string>()
            );
            command.AddOption(opt);

            command.Handler = CommandHandler.Create(typeof(Program).GetMethod(nameof(Decrypt), System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic));
            return command;
        }


        private static int Encrypt(DataProtectionScope scope, string entropy, string value) {
            var entropyBytes = string.IsNullOrWhiteSpace(entropy)
                    ? null
                    : Convert.FromBase64String(entropy);

            var bytes = Encoding.UTF8.GetBytes(value);
            var encrypted = Convert.ToBase64String(ProtectedData.Protect(bytes, entropyBytes, scope));

            Console.WriteLine();
            Console.WriteLine(encrypted);

            return 0;
        }


        private static int Decrypt(string entropy, string value) {
            var entropyBytes = string.IsNullOrWhiteSpace(entropy)
                    ? null
                    : Convert.FromBase64String(entropy);

            try {
                var bytes = Convert.FromBase64String(value);
                // Doesn't matter which scope is specified when decrypting. 
                // See https://stackoverflow.com/questions/19164926/data-protection-api-scope-localmachine-currentuser
                var decrypted = Encoding.UTF8.GetString(ProtectedData.Unprotect(bytes, entropyBytes, default));
                Console.WriteLine();
                Console.WriteLine(decrypted);
            }
            catch (CryptographicException e) {
                Console.WriteLine();
                Console.Error.WriteLine(e.Message);
                return 1;
            }

            return 0;
        }

    }
}
