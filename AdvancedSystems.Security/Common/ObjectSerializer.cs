using System;
using System.Buffers;
using System.Text.Json;

namespace AdvancedSystems.Security.Common
{
    public static class ObjectSerializer
    {
        public static ReadOnlySpan<byte> Serialize<T>(T value) where T : class, new()
        {
            var buffer = new ArrayBufferWriter<byte>();
            using var writer = new Utf8JsonWriter(buffer);
            JsonSerializer.Serialize<T>(writer, value);
            return buffer.WrittenSpan;
        }

        public static T Deserialize<T>(ReadOnlySpan<byte> values) where T : class, new()
        {
            var payload = new Utf8JsonReader(values);
            return JsonSerializer.Deserialize<T>(ref payload)!;
        }
    }
}
