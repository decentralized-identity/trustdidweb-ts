export const clone = (input: any) => JSON.parse(JSON.stringify(input));

export const createDate = (created?: Date) => new Date(created ?? Date.now()).toISOString().slice(0,-5)+'Z'