<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rules\Password;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string|max:30',
            'email' => 'required|string|email|unique:users,email',
            'password' => [
                'required',
                'confirmed',
                Password::min(8)
                        ->letters()
                        ->mixedCase()
                        ->numbers()
            ]
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password'])
        ]);
        $user->imageUrl = "https://ui-avatars.com/api/?name={$user->name}&size=128";
        $token = $user->createToken('main')->plainTextToken;
        return response()->json([
            'user'=>$user,
            'token'=>$token
        ], 200);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'email', 'string', 'exists:users,email'],
            'password' => ['required'],
            'remember' => ['boolean']
        ]);
        $remember = $credentials['remember'] ?? false;
        unset($credentials['remember']);
        if (!Auth::attempt($credentials, $remember)) {
            return response()->json([
                'message'=> 'The provided credentials do not match our records.'
            ], 422);
        }
        $user = Auth::user();
        $user->imageUrl = "https://ui-avatars.com/api/?name={$user->name}&size=128";
        $token = $user->createToken('main')->plainTextToken;

        return response()->json([
            'user'=>$user,
            'token'=>$token
        ], 200);
    }

    public function logout()
    {
        $user = Auth::user();
        $user->currentAccessToken()->delete();

        return response()->json([
            'success'=>true
        ], 200);
    }
}

