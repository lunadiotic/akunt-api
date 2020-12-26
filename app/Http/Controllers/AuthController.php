<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8'],
            'device_name' => ['required']
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        try {
            $data['password'] = Hash::make($request->password);

            $user = User::create($data);

            if (!Auth::attempt($request->only('email', 'password'))) {
                return response()->json([
                    'message' => 'The provided credentials are incorrect.',
                ], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $explodeToken = explode(
                "|",
                $user->createToken('token')->plainTextToken
            );

            return response()->json([
                'message' => 'Auth success',
                'data' => [
                    'user' => $user,
                    'token' => $explodeToken[1]
                ]
            ], Response::HTTP_CREATED);

        } catch (Exception $e) {
            return response()->json([
                'message' => "Failed " . $e->getMessage()
            ], 409);
        }
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => ['required', 'email'],
            'password' => ['required']
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        try {
            $user = User::where('email', $request->email)->first();

            if (! $user || ! Hash::check($request->password, $user->password)) {
                return response([
                    'message' => ['These credentials do not match our records.']
                ], 422);
            }

            $explodeToken = explode(
                "|",
                $user->createToken('token')->plainTextToken
            );

            return response()->json([
                'message' => 'Auth success',
                'data' => [
                    'user' => $user,
                    'token' => $explodeToken[1]
                ]
            ]);
        } catch (Exception $e) {
            return response()->json([
                'message' => "Failed " . $e->getMessage()
            ], 409);
        }
    }

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();
        return response()->json([
            'message' => 'log out success'
        ], Response::HTTP_OK);
    }
}
