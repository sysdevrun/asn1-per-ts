/** Flattens intersections into a single object type, for readable tooltips. */
export type Simplify<T> = { [K in keyof T]: T[K] } & {};
