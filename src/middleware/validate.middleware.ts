import { Request, Response, NextFunction } from 'express';
import { z, ZodSchema } from 'zod';

// ============================================
// VALIDATION MIDDLEWARE
// ============================================

type ValidationTarget = 'body' | 'query' | 'params';

/**
 * Create validation middleware for a Zod schema
 */
export function validate(schema: ZodSchema, target: ValidationTarget = 'body') {
    return (req: Request, res: Response, next: NextFunction): void => {
        try {
            const data = req[target];
            const result = schema.safeParse(data);

            if (!result.success) {
                const errors = result.error.errors.map((err) => ({
                    field: err.path.join('.'),
                    message: err.message,
                }));

                res.status(400).json({
                    success: false,
                    error: 'Validation failed',
                    code: 'VALIDATION_ERROR',
                    details: errors,
                });
                return;
            }

            // Replace request data with parsed (and transformed) data
            req[target] = result.data;
            next();
        } catch (error) {
            res.status(400).json({
                success: false,
                error: 'Invalid request data',
                code: 'INVALID_DATA',
            });
        }
    };
}

/**
 * Validate request body
 */
export function validateBody(schema: ZodSchema) {
    return validate(schema, 'body');
}

/**
 * Validate query parameters
 */
export function validateQuery(schema: ZodSchema) {
    return validate(schema, 'query');
}

/**
 * Validate route parameters
 */
export function validateParams(schema: ZodSchema) {
    return validate(schema, 'params');
}
