type Options = {
	period?: number
	algorithm?: string
	digits?: number
	timestamp?: string
}
declare function getToken(key: string, options: Options): string
export default getToken
