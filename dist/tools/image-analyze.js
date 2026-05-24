/**
 * image_analyze stub — VLM görsel analizi için FETIH built-in araçlarını kullan.
 * ctf-audio-analyzer ve ctf-ocr bu modülü import eder; MCP bridge modunda
 * gerçek VLM çağrısı FETIH Python tarafından yapılır.
 */
export const imageAnalyzeTool = {
    name: 'image_analyze',
    description: 'Bir görsel dosyasını VLM ile analiz et. ' +
        'MCP bridge modunda: FETIH built-in vision araçlarını kullan.',
    inputSchema: {
        type: 'object',
        properties: {
            image_path: { type: 'string', description: 'Görsel dosya yolu' },
            prompt: { type: 'string', description: 'Analiz sorusu' },
        },
        required: ['image_path'],
    },
    async execute(_input) {
        return {
            output: 'image_analyze: MCP bridge modunda doğrudan kullanılamaz. ' +
                "FETIH'in built-in vision araçlarıyla görsel analizi yap.",
            isError: false,
        };
    },
};
